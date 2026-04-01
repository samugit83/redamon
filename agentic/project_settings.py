"""
Agent Project Settings - Fetch agent configuration from webapp API

When PROJECT_ID and WEBAPP_API_URL are set as environment variables,
settings are fetched from the PostgreSQL database via webapp API.
Otherwise, falls back to DEFAULT_AGENT_SETTINGS for standalone usage.

Mirrors the pattern from recon/project_settings.py.
"""
import os
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

# DANGEROUS TOOLS — require manual confirmation before execution
DANGEROUS_TOOLS = frozenset({
    'execute_nmap', 'execute_naabu', 'execute_nuclei', 'execute_curl',
    'msf_restart', 'kali_shell', 'metasploit_console', 'execute_code',

    'execute_hydra', 'execute_playwright', 'execute_wpscan',
})

# DEFAULT SETTINGS - Used as fallback for standalone usage and missing API fields

DEFAULT_AGENT_SETTINGS: dict[str, Any] = {
    # LLM Configuration
    'OPENAI_MODEL': 'claude-opus-4-6',
    'INFORMATIONAL_SYSTEM_PROMPT': '',
    'EXPL_SYSTEM_PROMPT': '',
    'POST_EXPL_SYSTEM_PROMPT': '',

    # Stealth Mode
    'STEALTH_MODE': False,

    # Agent Guardrail
    'AGENT_GUARDRAIL_ENABLED': True,

    # Phase Configuration
    'ACTIVATE_POST_EXPL_PHASE': True,
    'POST_EXPL_PHASE_TYPE': 'statefull',

    # Payload Direction
    'LHOST': '',       # Empty string = not set
    'LPORT': None,      # None = not set
    'BIND_PORT_ON_TARGET': None,  # None = not set (agent will ask user)
    'PAYLOAD_USE_HTTPS': False,
    'NGROK_TUNNEL_ENABLED': False,
    'CHISEL_TUNNEL_ENABLED': False,

    # Agent Limits
    'MAX_ITERATIONS': 100,
    'EXECUTION_TRACE_MEMORY_STEPS': 100,
    'TOOL_OUTPUT_MAX_CHARS': 20000,

    # Approval Gates
    'REQUIRE_APPROVAL_FOR_EXPLOITATION': True,
    'REQUIRE_APPROVAL_FOR_POST_EXPLOITATION': True,
    'REQUIRE_TOOL_CONFIRMATION': True,

    # Neo4j
    'CYPHER_MAX_RETRIES': 3,

    # LLM Parse Retry
    'LLM_PARSE_MAX_RETRIES': 3,

    # Deep Think (Strategic Reasoning)
    'DEEP_THINK_ENABLED': False,

    # Debug
    'CREATE_GRAPH_IMAGE_ON_INIT': False,

    # Logging
    'LOG_MAX_MB': 10,
    'LOG_BACKUP_COUNT': 5,

    # Tool Phase Restrictions
    'TOOL_PHASE_MAP': {
        'query_graph': ['informational', 'exploitation', 'post_exploitation'],
        'execute_curl': ['informational', 'exploitation', 'post_exploitation'],
        'execute_naabu': ['informational', 'exploitation'],

        'execute_masscan': ['informational', 'exploitation'],
        'execute_wpscan': ['informational', 'exploitation'],
        'execute_nmap': ['informational', 'exploitation', 'post_exploitation'],
        'execute_nuclei': ['informational', 'exploitation'],
        'kali_shell': ['informational', 'exploitation', 'post_exploitation'],
        'execute_code': ['exploitation', 'post_exploitation'],
        'execute_playwright': ['informational', 'exploitation', 'post_exploitation'],
        'execute_hydra': ['exploitation', 'post_exploitation'],
        'metasploit_console': ['exploitation', 'post_exploitation'],
        'msf_restart': ['exploitation', 'post_exploitation'],
        'web_search': ['informational', 'exploitation', 'post_exploitation'],
        'shodan': ['informational', 'exploitation'],
        'google_dork': ['informational'],
    },

    # Kali Shell Library Installation
    'KALI_INSTALL_ENABLED': False,
    'KALI_INSTALL_ALLOWED_PACKAGES': '',
    'KALI_INSTALL_FORBIDDEN_PACKAGES': '',

    # Hydra Credential Testing
    'HYDRA_ENABLED': True,
    'HYDRA_THREADS': 16,
    'HYDRA_WAIT_BETWEEN_CONNECTIONS': 0,
    'HYDRA_CONNECTION_TIMEOUT': 32,
    'HYDRA_STOP_ON_FIRST_FOUND': True,
    'HYDRA_EXTRA_CHECKS': 'nsr',
    'HYDRA_VERBOSE': True,
    'HYDRA_MAX_WORDLIST_ATTEMPTS': 3,

    # Shodan OSINT
    'SHODAN_ENABLED': True,

    # Social Engineering Simulation
    'PHISHING_SMTP_CONFIG': '',  # Free-text SMTP config for phishing email delivery (optional)

    # Availability Testing
    'DOS_MAX_DURATION': 60,             # Max seconds per DoS attempt
    'DOS_MAX_ATTEMPTS': 3,              # Max different vectors to try
    'DOS_CONCURRENT_CONNECTIONS': 1000, # Connections for app-layer DoS (slowloris etc.)
    'DOS_ASSESSMENT_ONLY': False,       # True = only check vulnerability, don't attack

    # SQL Injection Testing
    'SQLI_LEVEL': 1,                    # sqlmap --level (1-5, higher = more payloads/injection points)
    'SQLI_RISK': 1,                     # sqlmap --risk (1-3, higher = more aggressive tests)
    'SQLI_TAMPER_SCRIPTS': '',          # Comma-separated tamper scripts (e.g., "space2comment,randomcase")

    # Attack Skill Configuration
    'ATTACK_SKILL_CONFIG': {
        'builtIn': {
            'cve_exploit': True,
            'brute_force_credential_guess': False,
            'phishing_social_engineering': False,
            'denial_of_service': False,
            'sql_injection': True,
        },
        'user': {},
    },
    'USER_ATTACK_SKILLS': [],  # Populated from DB when user skills are enabled

    # Legacy (deprecated — kept for backward compat)
    'BRUTE_FORCE_MAX_WORDLIST_ATTEMPTS': 3,
    'BRUTEFORCE_SPEED': 5,

    # Rules of Engagement
    'ROE_ENABLED': False,
    'ROE_RAW_TEXT': '',
    'ROE_CLIENT_NAME': '',
    'ROE_CLIENT_CONTACT_NAME': '',
    'ROE_CLIENT_CONTACT_EMAIL': '',
    'ROE_CLIENT_CONTACT_PHONE': '',
    'ROE_EMERGENCY_CONTACT': '',
    'ROE_ENGAGEMENT_START_DATE': '',
    'ROE_ENGAGEMENT_END_DATE': '',
    'ROE_ENGAGEMENT_TYPE': 'external',
    'ROE_EXCLUDED_HOSTS': [],
    'ROE_EXCLUDED_HOST_REASONS': [],
    'ROE_TIME_WINDOW_ENABLED': False,
    'ROE_TIME_WINDOW_TIMEZONE': 'UTC',
    'ROE_TIME_WINDOW_DAYS': ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'],
    'ROE_TIME_WINDOW_START_TIME': '09:00',
    'ROE_TIME_WINDOW_END_TIME': '18:00',
    'ROE_FORBIDDEN_TOOLS': [],
    'ROE_FORBIDDEN_CATEGORIES': [],
    'ROE_MAX_SEVERITY_PHASE': 'post_exploitation',
    'ROE_ALLOW_DOS': False,
    'ROE_ALLOW_SOCIAL_ENGINEERING': False,
    'ROE_ALLOW_PHYSICAL_ACCESS': False,
    'ROE_ALLOW_DATA_EXFILTRATION': False,
    'ROE_ALLOW_ACCOUNT_LOCKOUT': False,
    'ROE_ALLOW_PRODUCTION_TESTING': True,
    'ROE_GLOBAL_MAX_RPS': 0,
    'ROE_SENSITIVE_DATA_HANDLING': 'no_access',
    'ROE_DATA_RETENTION_DAYS': 90,
    'ROE_REQUIRE_DATA_ENCRYPTION': True,
    'ROE_STATUS_UPDATE_FREQUENCY': 'daily',
    'ROE_CRITICAL_FINDING_NOTIFY': True,
    'ROE_INCIDENT_PROCEDURE': '',
    'ROE_THIRD_PARTY_PROVIDERS': [],
    'ROE_COMPLIANCE_FRAMEWORKS': [],
    'ROE_NOTES': '',
}


def fetch_agent_settings(project_id: str, webapp_url: str) -> dict[str, Any]:
    """
    Fetch agent settings from webapp API.

    Args:
        project_id: The project ID to fetch settings for
        webapp_url: Base URL of the webapp API (e.g., http://localhost:3000)

    Returns:
        Dictionary of settings in SCREAMING_SNAKE_CASE format
    """
    import requests

    url = f"{webapp_url.rstrip('/')}/api/projects/{project_id}?includeSkillContent=true"
    logger.info(f"Fetching agent settings from {url}")

    response = requests.get(url, timeout=30)
    response.raise_for_status()
    project = response.json()

    # Start with defaults, then override with API values
    settings = DEFAULT_AGENT_SETTINGS.copy()

    # Map camelCase API fields to SCREAMING_SNAKE_CASE
    settings['OPENAI_MODEL'] = project.get('agentOpenaiModel', DEFAULT_AGENT_SETTINGS['OPENAI_MODEL'])
    settings['INFORMATIONAL_SYSTEM_PROMPT'] = project.get('agentInformationalSystemPrompt', DEFAULT_AGENT_SETTINGS['INFORMATIONAL_SYSTEM_PROMPT'])
    settings['EXPL_SYSTEM_PROMPT'] = project.get('agentExplSystemPrompt', DEFAULT_AGENT_SETTINGS['EXPL_SYSTEM_PROMPT'])
    settings['POST_EXPL_SYSTEM_PROMPT'] = project.get('agentPostExplSystemPrompt', DEFAULT_AGENT_SETTINGS['POST_EXPL_SYSTEM_PROMPT'])
    settings['ACTIVATE_POST_EXPL_PHASE'] = project.get('agentActivatePostExplPhase', DEFAULT_AGENT_SETTINGS['ACTIVATE_POST_EXPL_PHASE'])
    settings['POST_EXPL_PHASE_TYPE'] = project.get('agentPostExplPhaseType', DEFAULT_AGENT_SETTINGS['POST_EXPL_PHASE_TYPE'])
    settings['LHOST'] = project.get('agentLhost', DEFAULT_AGENT_SETTINGS['LHOST'])
    settings['LPORT'] = project.get('agentLport', DEFAULT_AGENT_SETTINGS['LPORT'])
    settings['BIND_PORT_ON_TARGET'] = project.get('agentBindPortOnTarget', DEFAULT_AGENT_SETTINGS['BIND_PORT_ON_TARGET'])
    settings['PAYLOAD_USE_HTTPS'] = project.get('agentPayloadUseHttps', DEFAULT_AGENT_SETTINGS['PAYLOAD_USE_HTTPS'])
    settings['NGROK_TUNNEL_ENABLED'] = project.get('agentNgrokTunnelEnabled', DEFAULT_AGENT_SETTINGS['NGROK_TUNNEL_ENABLED'])
    settings['CHISEL_TUNNEL_ENABLED'] = project.get('agentChiselTunnelEnabled', DEFAULT_AGENT_SETTINGS['CHISEL_TUNNEL_ENABLED'])
    settings['MAX_ITERATIONS'] = project.get('agentMaxIterations', DEFAULT_AGENT_SETTINGS['MAX_ITERATIONS'])
    settings['EXECUTION_TRACE_MEMORY_STEPS'] = project.get('agentExecutionTraceMemorySteps', DEFAULT_AGENT_SETTINGS['EXECUTION_TRACE_MEMORY_STEPS'])
    settings['REQUIRE_APPROVAL_FOR_EXPLOITATION'] = project.get('agentRequireApprovalForExploitation', DEFAULT_AGENT_SETTINGS['REQUIRE_APPROVAL_FOR_EXPLOITATION'])
    settings['REQUIRE_APPROVAL_FOR_POST_EXPLOITATION'] = project.get('agentRequireApprovalForPostExploitation', DEFAULT_AGENT_SETTINGS['REQUIRE_APPROVAL_FOR_POST_EXPLOITATION'])
    settings['REQUIRE_TOOL_CONFIRMATION'] = project.get('agentRequireToolConfirmation', DEFAULT_AGENT_SETTINGS['REQUIRE_TOOL_CONFIRMATION'])
    settings['TOOL_OUTPUT_MAX_CHARS'] = project.get('agentToolOutputMaxChars', DEFAULT_AGENT_SETTINGS['TOOL_OUTPUT_MAX_CHARS'])
    settings['CYPHER_MAX_RETRIES'] = project.get('agentCypherMaxRetries', DEFAULT_AGENT_SETTINGS['CYPHER_MAX_RETRIES'])
    settings['LLM_PARSE_MAX_RETRIES'] = project.get('agentLlmParseMaxRetries', DEFAULT_AGENT_SETTINGS['LLM_PARSE_MAX_RETRIES'])
    settings['DEEP_THINK_ENABLED'] = project.get('agentDeepThinkEnabled', DEFAULT_AGENT_SETTINGS['DEEP_THINK_ENABLED'])
    settings['CREATE_GRAPH_IMAGE_ON_INIT'] = project.get('agentCreateGraphImageOnInit', DEFAULT_AGENT_SETTINGS['CREATE_GRAPH_IMAGE_ON_INIT'])
    settings['LOG_MAX_MB'] = project.get('agentLogMaxMb', DEFAULT_AGENT_SETTINGS['LOG_MAX_MB'])
    settings['LOG_BACKUP_COUNT'] = project.get('agentLogBackupCount', DEFAULT_AGENT_SETTINGS['LOG_BACKUP_COUNT'])
    settings['TOOL_PHASE_MAP'] = project.get('agentToolPhaseMap', DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP'])
    settings['BRUTE_FORCE_MAX_WORDLIST_ATTEMPTS'] = project.get('agentBruteForceMaxWordlistAttempts', DEFAULT_AGENT_SETTINGS['BRUTE_FORCE_MAX_WORDLIST_ATTEMPTS'])
    settings['BRUTEFORCE_SPEED'] = project.get('agentBruteforceSpeed', DEFAULT_AGENT_SETTINGS['BRUTEFORCE_SPEED'])
    settings['KALI_INSTALL_ENABLED'] = project.get('agentKaliInstallEnabled', DEFAULT_AGENT_SETTINGS['KALI_INSTALL_ENABLED'])
    settings['KALI_INSTALL_ALLOWED_PACKAGES'] = project.get('agentKaliInstallAllowedPackages', DEFAULT_AGENT_SETTINGS['KALI_INSTALL_ALLOWED_PACKAGES'])
    settings['KALI_INSTALL_FORBIDDEN_PACKAGES'] = project.get('agentKaliInstallForbiddenPackages', DEFAULT_AGENT_SETTINGS['KALI_INSTALL_FORBIDDEN_PACKAGES'])
    settings['HYDRA_ENABLED'] = project.get('hydraEnabled', DEFAULT_AGENT_SETTINGS['HYDRA_ENABLED'])
    settings['HYDRA_THREADS'] = project.get('hydraThreads', DEFAULT_AGENT_SETTINGS['HYDRA_THREADS'])
    settings['HYDRA_WAIT_BETWEEN_CONNECTIONS'] = project.get('hydraWaitBetweenConnections', DEFAULT_AGENT_SETTINGS['HYDRA_WAIT_BETWEEN_CONNECTIONS'])
    settings['HYDRA_CONNECTION_TIMEOUT'] = project.get('hydraConnectionTimeout', DEFAULT_AGENT_SETTINGS['HYDRA_CONNECTION_TIMEOUT'])
    settings['HYDRA_STOP_ON_FIRST_FOUND'] = project.get('hydraStopOnFirstFound', DEFAULT_AGENT_SETTINGS['HYDRA_STOP_ON_FIRST_FOUND'])
    settings['HYDRA_EXTRA_CHECKS'] = project.get('hydraExtraChecks', DEFAULT_AGENT_SETTINGS['HYDRA_EXTRA_CHECKS'])
    settings['HYDRA_VERBOSE'] = project.get('hydraVerbose', DEFAULT_AGENT_SETTINGS['HYDRA_VERBOSE'])
    settings['HYDRA_MAX_WORDLIST_ATTEMPTS'] = project.get('hydraMaxWordlistAttempts', DEFAULT_AGENT_SETTINGS['HYDRA_MAX_WORDLIST_ATTEMPTS'])
    settings['SHODAN_ENABLED'] = project.get('shodanEnabled', DEFAULT_AGENT_SETTINGS['SHODAN_ENABLED'])
    settings['STEALTH_MODE'] = project.get('stealthMode', DEFAULT_AGENT_SETTINGS['STEALTH_MODE'])
    settings['AGENT_GUARDRAIL_ENABLED'] = project.get('agentGuardrailEnabled', DEFAULT_AGENT_SETTINGS['AGENT_GUARDRAIL_ENABLED'])
    settings['PHISHING_SMTP_CONFIG'] = project.get('phishingSmtpConfig', DEFAULT_AGENT_SETTINGS['PHISHING_SMTP_CONFIG'])
    settings['DOS_MAX_DURATION'] = project.get('dosMaxDuration', DEFAULT_AGENT_SETTINGS['DOS_MAX_DURATION'])
    settings['DOS_MAX_ATTEMPTS'] = project.get('dosMaxAttempts', DEFAULT_AGENT_SETTINGS['DOS_MAX_ATTEMPTS'])
    settings['DOS_CONCURRENT_CONNECTIONS'] = project.get('dosConcurrentConnections', DEFAULT_AGENT_SETTINGS['DOS_CONCURRENT_CONNECTIONS'])
    settings['DOS_ASSESSMENT_ONLY'] = project.get('dosAssessmentOnly', DEFAULT_AGENT_SETTINGS['DOS_ASSESSMENT_ONLY'])
    settings['ATTACK_SKILL_CONFIG'] = project.get('attackSkillConfig', DEFAULT_AGENT_SETTINGS['ATTACK_SKILL_CONFIG'])
    settings['USER_ATTACK_SKILLS'] = project.get('userAttackSkills', DEFAULT_AGENT_SETTINGS['USER_ATTACK_SKILLS'])

    # Target scope (used by guardrail checks inside the agent)
    settings['TARGET_DOMAIN'] = project.get('targetDomain', '')
    settings['IP_MODE'] = project.get('ipMode', False)
    settings['TARGET_IPS'] = project.get('targetIps', [])

    # Rules of Engagement
    settings['ROE_ENABLED'] = project.get('roeEnabled', DEFAULT_AGENT_SETTINGS['ROE_ENABLED'])
    settings['ROE_RAW_TEXT'] = project.get('roeRawText', DEFAULT_AGENT_SETTINGS['ROE_RAW_TEXT'])
    settings['ROE_CLIENT_NAME'] = project.get('roeClientName', DEFAULT_AGENT_SETTINGS['ROE_CLIENT_NAME'])
    settings['ROE_CLIENT_CONTACT_NAME'] = project.get('roeClientContactName', DEFAULT_AGENT_SETTINGS['ROE_CLIENT_CONTACT_NAME'])
    settings['ROE_CLIENT_CONTACT_EMAIL'] = project.get('roeClientContactEmail', DEFAULT_AGENT_SETTINGS['ROE_CLIENT_CONTACT_EMAIL'])
    settings['ROE_CLIENT_CONTACT_PHONE'] = project.get('roeClientContactPhone', DEFAULT_AGENT_SETTINGS['ROE_CLIENT_CONTACT_PHONE'])
    settings['ROE_EMERGENCY_CONTACT'] = project.get('roeEmergencyContact', DEFAULT_AGENT_SETTINGS['ROE_EMERGENCY_CONTACT'])
    settings['ROE_ENGAGEMENT_START_DATE'] = project.get('roeEngagementStartDate', DEFAULT_AGENT_SETTINGS['ROE_ENGAGEMENT_START_DATE'])
    settings['ROE_ENGAGEMENT_END_DATE'] = project.get('roeEngagementEndDate', DEFAULT_AGENT_SETTINGS['ROE_ENGAGEMENT_END_DATE'])
    settings['ROE_ENGAGEMENT_TYPE'] = project.get('roeEngagementType', DEFAULT_AGENT_SETTINGS['ROE_ENGAGEMENT_TYPE'])
    settings['ROE_EXCLUDED_HOSTS'] = project.get('roeExcludedHosts', DEFAULT_AGENT_SETTINGS['ROE_EXCLUDED_HOSTS'])
    settings['ROE_EXCLUDED_HOST_REASONS'] = project.get('roeExcludedHostReasons', DEFAULT_AGENT_SETTINGS['ROE_EXCLUDED_HOST_REASONS'])
    settings['ROE_TIME_WINDOW_ENABLED'] = project.get('roeTimeWindowEnabled', DEFAULT_AGENT_SETTINGS['ROE_TIME_WINDOW_ENABLED'])
    settings['ROE_TIME_WINDOW_TIMEZONE'] = project.get('roeTimeWindowTimezone', DEFAULT_AGENT_SETTINGS['ROE_TIME_WINDOW_TIMEZONE'])
    settings['ROE_TIME_WINDOW_DAYS'] = project.get('roeTimeWindowDays', DEFAULT_AGENT_SETTINGS['ROE_TIME_WINDOW_DAYS'])
    settings['ROE_TIME_WINDOW_START_TIME'] = project.get('roeTimeWindowStartTime', DEFAULT_AGENT_SETTINGS['ROE_TIME_WINDOW_START_TIME'])
    settings['ROE_TIME_WINDOW_END_TIME'] = project.get('roeTimeWindowEndTime', DEFAULT_AGENT_SETTINGS['ROE_TIME_WINDOW_END_TIME'])
    settings['ROE_FORBIDDEN_TOOLS'] = project.get('roeForbiddenTools', DEFAULT_AGENT_SETTINGS['ROE_FORBIDDEN_TOOLS'])
    settings['ROE_FORBIDDEN_CATEGORIES'] = project.get('roeForbiddenCategories', DEFAULT_AGENT_SETTINGS['ROE_FORBIDDEN_CATEGORIES'])
    settings['ROE_MAX_SEVERITY_PHASE'] = project.get('roeMaxSeverityPhase', DEFAULT_AGENT_SETTINGS['ROE_MAX_SEVERITY_PHASE'])
    settings['ROE_ALLOW_DOS'] = project.get('roeAllowDos', DEFAULT_AGENT_SETTINGS['ROE_ALLOW_DOS'])
    settings['ROE_ALLOW_SOCIAL_ENGINEERING'] = project.get('roeAllowSocialEngineering', DEFAULT_AGENT_SETTINGS['ROE_ALLOW_SOCIAL_ENGINEERING'])
    settings['ROE_ALLOW_PHYSICAL_ACCESS'] = project.get('roeAllowPhysicalAccess', DEFAULT_AGENT_SETTINGS['ROE_ALLOW_PHYSICAL_ACCESS'])
    settings['ROE_ALLOW_DATA_EXFILTRATION'] = project.get('roeAllowDataExfiltration', DEFAULT_AGENT_SETTINGS['ROE_ALLOW_DATA_EXFILTRATION'])
    settings['ROE_ALLOW_ACCOUNT_LOCKOUT'] = project.get('roeAllowAccountLockout', DEFAULT_AGENT_SETTINGS['ROE_ALLOW_ACCOUNT_LOCKOUT'])
    settings['ROE_ALLOW_PRODUCTION_TESTING'] = project.get('roeAllowProductionTesting', DEFAULT_AGENT_SETTINGS['ROE_ALLOW_PRODUCTION_TESTING'])
    settings['ROE_GLOBAL_MAX_RPS'] = project.get('roeGlobalMaxRps', DEFAULT_AGENT_SETTINGS['ROE_GLOBAL_MAX_RPS'])
    settings['ROE_SENSITIVE_DATA_HANDLING'] = project.get('roeSensitiveDataHandling', DEFAULT_AGENT_SETTINGS['ROE_SENSITIVE_DATA_HANDLING'])
    settings['ROE_DATA_RETENTION_DAYS'] = project.get('roeDataRetentionDays', DEFAULT_AGENT_SETTINGS['ROE_DATA_RETENTION_DAYS'])
    settings['ROE_REQUIRE_DATA_ENCRYPTION'] = project.get('roeRequireDataEncryption', DEFAULT_AGENT_SETTINGS['ROE_REQUIRE_DATA_ENCRYPTION'])
    settings['ROE_STATUS_UPDATE_FREQUENCY'] = project.get('roeStatusUpdateFrequency', DEFAULT_AGENT_SETTINGS['ROE_STATUS_UPDATE_FREQUENCY'])
    settings['ROE_CRITICAL_FINDING_NOTIFY'] = project.get('roeCriticalFindingNotify', DEFAULT_AGENT_SETTINGS['ROE_CRITICAL_FINDING_NOTIFY'])
    settings['ROE_INCIDENT_PROCEDURE'] = project.get('roeIncidentProcedure', DEFAULT_AGENT_SETTINGS['ROE_INCIDENT_PROCEDURE'])
    settings['ROE_THIRD_PARTY_PROVIDERS'] = project.get('roeThirdPartyProviders', DEFAULT_AGENT_SETTINGS['ROE_THIRD_PARTY_PROVIDERS'])
    settings['ROE_COMPLIANCE_FRAMEWORKS'] = project.get('roeComplianceFrameworks', DEFAULT_AGENT_SETTINGS['ROE_COMPLIANCE_FRAMEWORKS'])
    settings['ROE_NOTES'] = project.get('roeNotes', DEFAULT_AGENT_SETTINGS['ROE_NOTES'])

    # --- Fetch user-level LLM providers and settings from DB ---
    user_id = project.get('userId', '')
    if user_id and webapp_url:
        # Fetch LLM providers (with full API keys via ?internal=true)
        try:
            providers_resp = requests.get(
                f"{webapp_url.rstrip('/')}/api/users/{user_id}/llm-providers?internal=true",
                timeout=10,
            )
            providers_resp.raise_for_status()
            settings['USER_LLM_PROVIDERS'] = providers_resp.json()
        except Exception as e:
            logger.warning(f"Failed to fetch user LLM providers: {e}")
            settings['USER_LLM_PROVIDERS'] = []

        # Fetch user settings (Tavily API key)
        try:
            user_settings_resp = requests.get(
                f"{webapp_url.rstrip('/')}/api/users/{user_id}/settings?internal=true",
                timeout=10,
            )
            user_settings_resp.raise_for_status()
            settings['USER_SETTINGS'] = user_settings_resp.json()
        except Exception as e:
            logger.warning(f"Failed to fetch user settings: {e}")
            settings['USER_SETTINGS'] = {}

        # If selected model is custom/, extract its specific config
        model_id = settings.get('OPENAI_MODEL', '')
        if model_id.startswith('custom/'):
            config_id = model_id[len('custom/'):]
            providers = settings.get('USER_LLM_PROVIDERS', [])
            matched = None
            for p in providers:
                if p.get('id') == config_id:
                    matched = p
                    break

            if not matched and providers:
                # Provider ID is stale (deleted & recreated). Fall back to the
                # user's first compatible provider so the agent isn't stuck.
                matched = providers[0]
                logger.warning(
                    f"Custom LLM config {config_id} not found; "
                    f"falling back to provider {matched['id']} ({matched.get('name')})"
                )
                settings['OPENAI_MODEL'] = f"custom/{matched['id']}"

            if matched:
                settings['CUSTOM_LLM_CONFIG'] = matched
            else:
                logger.warning(f"Custom LLM config {config_id} not found and no providers available")
                settings['CUSTOM_LLM_CONFIG'] = None
    else:
        settings['USER_LLM_PROVIDERS'] = []
        settings['USER_SETTINGS'] = {}

    logger.info(f"Loaded {len(settings)} agent settings for project {project_id}")
    return settings


def get_settings() -> dict[str, Any]:
    """
    Get current agent settings.

    Returns cached settings if loaded for a project, otherwise defaults.
    Use load_project_settings() to fetch settings for a specific project.

    Returns:
        Dictionary of settings in SCREAMING_SNAKE_CASE format
    """
    global _settings
    if _settings is not None:
        return _settings
    # Return defaults until a project is loaded
    logger.info("Using DEFAULT_AGENT_SETTINGS (no project loaded yet)")
    return DEFAULT_AGENT_SETTINGS.copy()


# Singleton settings instance
_settings: Optional[dict[str, Any]] = None
_current_project_id: Optional[str] = None


def load_project_settings(project_id: str) -> dict[str, Any]:
    """
    Fetch settings for a specific project from webapp API.

    Called by the orchestrator on every invocation to ensure settings
    reflect the latest values saved in the database.

    Args:
        project_id: The project ID received from the frontend

    Returns:
        Dictionary of settings in SCREAMING_SNAKE_CASE format
    """
    global _settings, _current_project_id

    webapp_url = os.environ.get('WEBAPP_API_URL')

    if not webapp_url:
        logger.warning("WEBAPP_API_URL not set, using DEFAULT_AGENT_SETTINGS")
        _settings = DEFAULT_AGENT_SETTINGS.copy()
        _current_project_id = project_id
        return _settings

    try:
        _settings = fetch_agent_settings(project_id, webapp_url)
        _current_project_id = project_id
        logger.info(f"Loaded {len(_settings)} agent settings from API for project {project_id}")
        return _settings

    except Exception as e:
        logger.error(f"Failed to fetch agent settings for project {project_id}: {e}")
        logger.warning("Falling back to DEFAULT_AGENT_SETTINGS")
        _settings = DEFAULT_AGENT_SETTINGS.copy()
        _current_project_id = project_id
        return _settings


def get_setting(key: str, default: Any = None) -> Any:
    """
    Get a single agent setting value.

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


# ATTACK SKILL HELPERS

def get_enabled_builtin_skills() -> set[str]:
    """Return the set of enabled built-in attack skill IDs."""
    config = get_setting('ATTACK_SKILL_CONFIG', {})
    return {k for k, v in config.get('builtIn', {}).items() if v}


def get_enabled_user_skills() -> list[dict]:
    """Return list of enabled user attack skills (id, name, content)."""
    config = get_setting('ATTACK_SKILL_CONFIG', {})
    user_toggles = config.get('user', {})
    return [s for s in get_setting('USER_ATTACK_SKILLS', [])
            if user_toggles.get(s['id'], True)]


# TOOL PHASE RESTRICTION HELPERS (moved from params.py)

def is_tool_allowed_in_phase(tool_name: str, phase: str) -> bool:
    """Check if a tool is allowed in the given phase."""
    tool_phase_map = get_setting('TOOL_PHASE_MAP', {})
    allowed_phases = tool_phase_map.get(tool_name, [])
    return phase in allowed_phases


def get_allowed_tools_for_phase(phase: str) -> list:
    """Get list of tool names allowed in the given phase."""
    tool_phase_map = get_setting('TOOL_PHASE_MAP', {})
    return [
        tool_name
        for tool_name, allowed_phases in tool_phase_map.items()
        if phase in allowed_phases
    ]


def get_hydra_flags_from_settings() -> str:
    """Build Hydra CLI flags string from project settings.

    Returns a pre-formatted flag string like: -t 16 -f -e nsr -V
    Injected into brute force prompts so the LLM uses project-configured values.
    """
    parts = []
    parts.append(f"-t {get_setting('HYDRA_THREADS', 16)}")
    wait = get_setting('HYDRA_WAIT_BETWEEN_CONNECTIONS', 0)
    if wait > 0:
        parts.append(f"-W {wait}")
    timeout = get_setting('HYDRA_CONNECTION_TIMEOUT', 32)
    if timeout != 32:
        parts.append(f"-w {timeout}")
    if get_setting('HYDRA_STOP_ON_FIRST_FOUND', True):
        parts.append("-f")
    extra = get_setting('HYDRA_EXTRA_CHECKS', 'nsr')
    if extra:
        parts.append(f"-e {extra}")
    if get_setting('HYDRA_VERBOSE', True):
        parts.append("-V")
    return " ".join(parts)


def get_dos_settings_dict() -> dict:
    """Get DoS settings as a dict for prompt template injection."""
    return {
        'dos_max_duration': get_setting('DOS_MAX_DURATION', 60),
        'dos_max_attempts': get_setting('DOS_MAX_ATTEMPTS', 3),
        'dos_connections': get_setting('DOS_CONCURRENT_CONNECTIONS', 1000),
    }

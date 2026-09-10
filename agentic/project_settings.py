"""
Agent Project Settings - Fetch agent configuration from webapp API

When PROJECT_ID and WEBAPP_API_URL are set as environment variables,
settings are fetched from the PostgreSQL database via webapp API.
Otherwise, falls back to DEFAULT_AGENT_SETTINGS for standalone usage.

Mirrors the pattern from recon/project_settings.py.
"""
import os
import logging
import contextvars
import re
from typing import Any, Optional

logger = logging.getLogger(__name__)

INTERNAL_HEADERS = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}

# =============================================================================
# DANGEROUS TOOLS — require manual confirmation before execution
# =============================================================================
DANGEROUS_TOOLS = frozenset({
    'execute_nmap', 'execute_naabu', 'execute_nuclei', 'execute_curl',
    'execute_httpx', 'msf_restart', 'kali_shell', 'metasploit_console',
    'execute_code', 'execute_hydra', 'execute_playwright', 'execute_wpscan',
    'execute_arjun', 'execute_ffuf', 'execute_amass', 'execute_gau',
    'execute_katana',
    # proxy_brain runs agent-authored code that can emit live traffic (its
    # redamon.replay/fuzz path). One confirmation authorizes a bounded campaign;
    # the per-send budget + host-pin bound the blast radius (plan §10).
    'proxy_brain',
    # Supply-chain L3: execute_guarddog downloads attacker-authored tarballs
    # (registry egress). execute_osv_scanner is passive/offline -> NOT dangerous.
    'execute_guarddog',
})

# =============================================================================
# FIRETEAM MUTEX GROUPS — tools with singleton state inside Kali sandbox
# Two fireteam members cannot concurrently claim the same group.
# =============================================================================
TOOL_MUTEX_GROUPS = {
    'metasploit': frozenset({'metasploit_console', 'msf_restart'}),
}

# =============================================================================
# DEFAULT SETTINGS - Used as fallback for standalone usage and missing API fields
# =============================================================================

DEFAULT_AGENT_SETTINGS: dict[str, Any] = {
    # LLM Configuration
    'OPENAI_MODEL': 'claude-opus-4-6',
    'INFORMATIONAL_SYSTEM_PROMPT': '',
    'EXPL_SYSTEM_PROMPT': '',
    'POST_EXPL_SYSTEM_PROMPT': '',
    # Anthropic prompt caching for the root think_node's system prompt.
    # When True, the static prefix (persona + tool registry + attack skill)
    # is marked cache_control={"type": "ephemeral"} so Anthropic caches it
    # once per session and bills subsequent reads at ~10% of base input cost.
    # Has no effect on non-Anthropic providers (gated by isinstance check).
    'ANTHROPIC_PROMPT_CACHING_ENABLED': True,

    # HTTP Traffic Capture (mitmproxy, Phase 1) — per-project routing gate for
    # the agent's target-facing tools (same flag recon reads).
    'CAPTURE_PROXY_ENABLED': False,

    # Stealth Mode
    'STEALTH_MODE': False,

    # Agent Guardrail
    'AGENT_GUARDRAIL_ENABLED': True,

    # Fireteam (multi-agent deployment). Gated by PERSISTENT_CHECKPOINTER=true.
    'PERSISTENT_CHECKPOINTER': True,             # master prerequisite for FIRETEAM_ENABLED
    'FIRETEAM_ENABLED': True,                    # master switch, maps from Project.fireteamEnabled
    'FIRETEAM_MAX_CONCURRENT': 5,                # asyncio.Semaphore permits
    'FIRETEAM_MAX_MEMBERS': 5,                   # hard cap on members per fireteam
    'FIRETEAM_MEMBER_MAX_ITERATIONS': 10,        # per-member ReAct iteration budget
    'FIRETEAM_TIMEOUT_SEC': 7200,                  # wall-clock per fireteam (raised to accommodate 30-min tool timeouts)
    'FIRETEAM_ALLOWED_PHASES': ['informational', 'exploitation', 'post_exploitation'],
    'FIRETEAM_CONFIRMATION_TIMEOUT_SEC': 600,    # how long a member waits for operator approval before auto-rejecting
    'FIRETEAM_PROPENSITY': 3,                    # 1-5 scalar: how strongly LLM is pushed to deploy fireteams (3=baseline, 1=reluctant, 5=aggressive)

    # LATS (Language Agent Tree Search) — bounded exploit-path search.
    # See internal/LATS_integration.md §8 "Settings summary". Ships OFF by
    # default (new projects run the plain sequential agent); enable per project
    # in Settings. When enabled it DRIVES by default; flip SHADOW on to
    # build+stream the tree without letting it drive (observe-only).
    'LATS_ENABLED': False,                        # master switch (default OFF)
    'LATS_SHADOW_MODE': False,                    # drive by default; True = observe-only (build the tree, do NOT drive)
    'LATS_ALLOWED_PHASES': ['exploitation'],     # phases where the tree search runs (post_exploitation experimental, §6.1)
    'LATS_MIN_HYPOTHESES': 2,                     # min credible probes lats_expand must yield to activate
    'LATS_BRANCHING': 6,                          # max candidate probes per Expand (tree width)
    'LATS_MAX_DEPTH': 6,                          # max chain length from root; node at this depth cannot expand further
    'LATS_MAX_ROLLOUTS': 50,                      # max Select->Backprop cycles = max live probes per objective
    'LATS_MAX_TREE_NODES': 120,                   # hard tree-size (total node) cap
    'LATS_UCT_C': 1.4,                            # exploration constant (focus vs breadth)
    'LATS_PRUNE_FLOOR': 0.15,                     # value below which a cold branch is pruned
    'LATS_RESPECT_GUIDANCE': True,                # graft operator guidance as a high-prior probe (§21.1)
    'LATS_VERIFY_TERMINAL': False,               # verify a claimed foothold before declaring success (§20.15)
    'LATS_REACTIVE_TRIGGERS': False,             # also activate on axis lock-in (deferred, §14)
    'LATS_SUMMARY_MAX_NODES': 40,                 # Fix A: max nodes rendered in the carried-forward tree summary
    'LATS_REACTIVATE_COOLDOWN': 4,                # Fix B2: min iterations between an archive and the next activation
    'LATS_REACTIVATE_STUCK_TURNS': 5,             # Fix B2: no-state-growth turns that re-trigger LATS without Deep Think (halfway to Deep Think's hard stall override of 10; above the reactivate cooldown)
    'LATS_SCORE_THRESHOLD': 3.0,                  # Fix B2: productivity score that re-triggers LATS. Kept strictly BELOW PRODUCTIVITY_SCORE_DEEPTHINK_THRESHOLD (4.0) so LATS stays the cheaper first responder in the [3.0, 4.0) band; the churn-aware score (Proposal 3) makes the score climb during recon-diffusion, so LATS now engages early with budget to spare.
    'LATS_DIGEST_MAX': 8,                         # max prior-tree digests accumulated + fed to each new tree's seed
    'LATS_PROBE_LEDGER_MAX': 400,                 # max executed probe keys retained in the cross-tree dedup ledger (§3): a later tree HARD-drops a byte-identical re-run of any probe a prior tree already ran
    'LATS_RESET_DEBOUNCE': 2,                      # a live tree is torn down only after a reset condition (phase/skill/target/objective change) holds this many CONSECUTIVE turns; a one-turn jitter blip (transient blank, oscillation) is ignored. task_complete is exempt (immediate).
    'LATS_STOP_ON_FOOTHOLD': False,               # when True, a mid-chain foothold finding (exploit_success/access_gained/rce/...) stops LATS — both BLOCKS activation and RESETS a live tree ("exploit path found, hand back"). OFF for flag-hunts, where a foothold is a MEANS, not the objective, so stopping early loses the tree before it reaches the flag.
    'LATS_LOG_EXPAND_PROMPT': False,              # diagnostic: dump the real LATS expand prompt to the log; on-demand only
    # GROUNDING (full-context parity): when on, LATS's expand receives EVERYTHING the
    # normal think node receives — the rendered attack-chain context (execution trace →
    # real discovered endpoints/params/observations), full target_info, RoE/scope, the
    # full built-in skill WORKFLOW + tool docs, the skill menu, and the Agent/Chat skills
    # catalog — instead of the old compressed situational block that starved it of the
    # real surface (empty Recon surface → hallucinated endpoints). LATS_CONTEXT_WINDOW caps
    # the chain-context history (recent iterations) to bound the per-expand token cost.
    'LATS_FULL_CONTEXT': True,
    'LATS_CONTEXT_WINDOW': 12,

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

    # Tradecraft Lookup tool
    # (Output truncation is delegated to the global TOOL_OUTPUT_MAX_CHARS so
    # tradecraft results follow the same cap as every other tool.)
    'TRADECRAFT_TOOL_ENABLED': True,
    'TRADECRAFT_FETCH_TIMEOUT': 30,
    'TRADECRAFT_DEFAULT_TTL_SEC': 86400,
    'TRADECRAFT_TIER2_THRESHOLD_BYTES': 800,
    'TRADECRAFT_SECTION_PICKER_MODEL': 'claude-haiku-4-5-20251001',
    'TRADECRAFT_CRAWL_MAX_PAGES': 30,
    'TRADECRAFT_CRAWL_MAX_LLM_CALLS': 20,
    'TRADECRAFT_CRAWL_TIME_BUDGET_SEC': 180,
    'TRADECRAFT_CRAWL_MAX_DEPTH': 3,

    # Agent Limits
    'MAX_ITERATIONS': 100,
    'EXECUTION_TRACE_MEMORY_STEPS': 100,
    'TOOL_OUTPUT_MAX_CHARS': 40000,
    # Cap on concurrent tools inside ONE plan_tools wave. Applies to both the
    # root agent and every fireteam member because both paths execute through
    # execute_plan_node. Semaphore semantics: a 20-step plan with cap=10 runs
    # the first 10 immediately and queues the other 10 on the semaphore, so
    # no tool is dropped. Primary purpose: prevent SSE head-of-line blocking
    # on the MCP kali-sandbox stream (which tripped sse_read_timeout under
    # heavy fan-out and forced agent-container restarts pre-reconnect-fix).
    'PLAN_MAX_PARALLEL_TOOLS': 10,

    # Approval Gates
    'REQUIRE_APPROVAL_FOR_EXPLOITATION': True,
    'REQUIRE_APPROVAL_FOR_POST_EXPLOITATION': True,
    'REQUIRE_TOOL_CONFIRMATION': True,
    # Behavior-triggered phase switch (Proposal 1): when the agent switches to an
    # OFFENSIVE attack skill (rce/sqli/xss/ssrf/path_traversal/cve/brute_force) while
    # still in the informational phase, auto-request the exploitation transition —
    # the phase should follow what the agent is actually doing, not wait for a
    # separate manual `transition_phase` action it tends to neglect. Still honors
    # REQUIRE_APPROVAL_FOR_EXPLOITATION (requests approval instead of flipping when on).
    'AUTO_TRANSITION_ON_ATTACK_SKILL': True,

    # Neo4j
    'CYPHER_MAX_RETRIES': 3,

    # LLM Parse Retry
    'LLM_PARSE_MAX_RETRIES': 3,

    # Knowledge Base
    # Precedence for KB_* keys with a kb_config.yaml equivalent: 
    # webapp API settings (when configured; TBD) → kb_config.yaml value → kb_config.py DEFAULTS dict.
    # "None" preserves whatever the YAML loaded at construction time.
    'KB_ENABLED': None,            # None = inherit from kb_config.yaml (KB_ENABLED top-level)
    'KB_SCORE_THRESHOLD': None,    # None = inherit from retrieval.score_threshold
    'KB_TOP_K': None,              # None = inherit from retrieval.top_k
    'KB_FALLBACK_TO_WEB': True,    # Agent-level, no yaml equivalent
    'KB_ENABLED_SOURCES': None,    # Project-wide allowlist: None = all sources; list to restrict
    'KB_MMR_ENABLED': None,        # None = inherit from mmr.enabled
    'KB_MMR_LAMBDA': None,         # None = inherit from mmr.lambda
    'KB_OVERFETCH_FACTOR': None,   # None = inherit from retrieval.overfetch_factor
    'KB_SOURCE_BOOSTS': None,      # None = inherit from source_boosts block; dict = merge overrides

    # Productivity Audit & Loop Detection
    # The orchestrator audits the LLM's per-step productivity verdict
    # (no_progress / duplicate / blocked / new_info / confirmation) and counts
    # unproductive steps in a sliding window. When the count crosses the
    # threshold, Deep Think is triggered (if enabled) and a prompt warning is
    # injected. Catches "successful but useless" tool calls (HTTP 200 with
    # empty body, identical fuzzing fingerprints, stable 404s) that the
    # legacy keyword-only failure detector missed.
    'PRODUCTIVITY_AUDIT_WINDOW': 6,         # how many recent steps the audit considers
    'UNPRODUCTIVE_STREAK_THRESHOLD': 3,     # unproductive steps in window to trigger pivot

    # Response-uniformity anomaly detector: complements the productivity audit
    # by catching streaks of DIFFERENT payloads that return IDENTICAL short-
    # duration failures (signature of probes being rejected at parse time
    # before reaching the layer the agent thinks it's testing).
    #
    # Calibration history: original defaults (window=8, min=5, ms=50) were
    # tuned for tight back-to-back probe bursts on localhost targets and
    # never fired on real sessions — agents interleave probes across
    # hypothesis classes, so 5 same-shape responses in 8 most-recent calls
    # is unrealistic; and parse-time crashes on networked targets land at
    # 100-150ms, above the 50ms "fast" threshold. Widened to catch the
    # dispersed-probe pattern that real agents actually produce.
    'UNIFORM_RESPONSE_WINDOW': 25,          # how many recent steps to consider
    'UNIFORM_RESPONSE_MIN_COUNT': 3,        # min identical-signature steps to fire
    'UNIFORM_RESPONSE_DURATION_MS': 200,    # below this ms, response is "front-door fast" (includes networked overhead)

    # Productivity scoring v2 — continuous score replacing the binary 3/6
    # streak counter. The score is a weighted sum of five observed signals:
    # unproductive verdicts, iterations-since-state-grew, max axis-repeat
    # count, same-pattern recent calls, minus rewards for recent new_info and
    # actionable_findings. Tiered actions (hint / Deep Think / require
    # justification / block) are triggered by configurable score thresholds.
    'PRODUCTIVITY_SCORE_ENABLED': True,      # master switch; if False, falls back to legacy 3/6
    'PRODUCTIVITY_SCORE_HINT_THRESHOLD': 3.0,
    'PRODUCTIVITY_SCORE_DEEPTHINK_THRESHOLD': 4.0,
    'PRODUCTIVITY_SCORE_REQUIRE_PIVOT_THRESHOLD': 7.0,
    'PRODUCTIVITY_SCORE_BLOCK_THRESHOLD': 9.0,
    # Churn-aware score (Proposal 3): map-growth (new endpoints/params) is recon
    # breadth, NOT convergence. Once the run goes NOVELTY_SATURATION_GRACE think
    # iterations without a CHAIN-advance (a confirmed finding / foothold), the
    # novelty reward decays so pure enumeration stops pinning the score to green —
    # letting the tier ladder (hint -> deep think -> pivot) fire on real stall.
    'PRODUCTIVITY_CHURN_AWARE': True,
    'PRODUCTIVITY_NOVELTY_SATURATION_GRACE': 3,
    'DEEP_THINK_COOLDOWN_ITERATIONS': 5,     # min iterations between Deep Thinks (override on self-request or critical score)
    'DEEP_THINK_NOVELTY_JACCARD_MAX': 0.6,   # if new priority_order >= this similarity to prior, reject and re-prompt
    'STATE_GROWTH_SOFT_HINT_THRESHOLD': 5,   # iterations since state grew → soft hint
    'STATE_GROWTH_HARD_THRESHOLD': 10,       # iterations since state grew → Deep Think override
    'AXIS_REPEAT_WARN_COUNT': 2,             # 2nd same-axis attempt → warn
    'AXIS_REPEAT_REQUIRE_PIVOT_COUNT': 3,    # 3rd same-axis attempt → require what_is_different
    'AXIS_REPEAT_BLOCK_COUNT': 4,            # 4th same-axis attempt → block

    # Debug
    'CREATE_GRAPH_IMAGE_ON_INIT': False,

    # Logging
    'LOG_MAX_MB': 10,
    'LOG_BACKUP_COUNT': 5,
    # Process-global, read once at startup by logging_config.setup_logging: when
    # True, each session's records go to logs/agent.<session_id>.log (with
    # agent.log kept as the fallback for unscoped records).
    'LOG_PER_SESSION': True,
    # Emit the machine-readable per-session event stream (agent.<sid>.events.jsonl).
    'LOG_EVENT_STREAM': True,
    # When True, dump the full system prompt EVERY iteration and the raw LLM
    # response. Off by default: the full prompt is logged once (iteration 1) and
    # the structured THOUGHT/REASONING/ACTION block already carries the response.
    'LOG_LLM_VERBOSE': False,
    # Max chars of a tool's output written to the prose log; the full body still
    # goes to the offload file + DB. Prose log keeps a bounded head for context.
    'LOG_TOOL_OUTPUT_MAX_CHARS': 4000,

    # Tool Phase Restrictions
    'TOOL_PHASE_MAP': {
        'query_graph': ['informational', 'exploitation', 'post_exploitation'],
        # proxy_brain is the single traffic tool (replaces proxy_search/get/
        # sitemap/params/grep/diff/to_curl/query/replay/fuzz). Available in all
        # phases so read/decode recon stays usable; active sends (redamon.replay/
        # fuzz) are refused outside exploitation by /traffic/replay itself.
        'proxy_brain': ['informational', 'exploitation', 'post_exploitation'],
        'execute_curl': ['informational', 'exploitation', 'post_exploitation'],
        'execute_naabu': ['informational', 'exploitation'],
        'execute_httpx': ['informational', 'exploitation'],
        'execute_subfinder': ['informational', 'exploitation'],
        'execute_wpscan': ['informational', 'exploitation'],
        'execute_jsluice': ['informational', 'exploitation'],
        'execute_amass': ['informational', 'exploitation'],
        'execute_arjun': ['informational', 'exploitation'],
        'execute_ffuf': ['informational', 'exploitation'],
        'execute_gau': ['informational', 'exploitation'],
        'execute_katana': ['informational', 'exploitation'],
        'execute_nmap': ['informational', 'exploitation', 'post_exploitation'],
        'execute_nuclei': ['informational', 'exploitation'],
        'kali_shell': ['informational', 'exploitation', 'post_exploitation'],
        'execute_code': ['informational', 'exploitation', 'post_exploitation'],
        'execute_playwright': ['informational', 'exploitation', 'post_exploitation'],
        'execute_hydra': ['exploitation', 'post_exploitation'],
        'metasploit_console': ['exploitation', 'post_exploitation'],
        'msf_restart': ['exploitation', 'post_exploitation'],
        'web_search': ['informational', 'exploitation', 'post_exploitation'],
        'cve_intel': ['informational', 'exploitation', 'post_exploitation'],
        # Supply-chain L3. osv-scanner is passive/offline -> all phases.
        # guarddog downloads untrusted code -> informational + exploitation only.
        'execute_osv_scanner': ['informational', 'exploitation', 'post_exploitation'],
        'execute_guarddog': ['informational', 'exploitation'],
        'shodan': ['informational', 'exploitation', 'post_exploitation'],
        'google_dork': ['informational'],
        'tradecraft_lookup': ['exploitation', 'post_exploitation'],
    },

    # User-managed MCP servers (UI-driven, see /settings/mcp). Stored as raw
    # JSON list; parsed via mcp_registry.parse_user_servers() at orchestrator
    # setup time.
    'USER_MCP_SERVERS': [],

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

    # XSS Testing
    'XSS_DALFOX_ENABLED': True,           # Allow dalfox automated WAF evasion when manual payloads fail
    'XSS_BLIND_CALLBACK_ENABLED': False,  # Allow interactsh-based blind XSS callbacks (sends data OOB to oast.fun)
    'XSS_CSP_BYPASS_ENABLED': True,       # Include CSP bypass guidance in the workflow prompt

    # SSRF Testing
    'SSRF_OOB_CALLBACK_ENABLED': True,        # Allow interactsh blind-SSRF callbacks (sends DNS/HTTP probes via oast.fun)
    'SSRF_CLOUD_METADATA_ENABLED': True,      # Allow cloud-metadata pivots (AWS IMDS, GCP/Azure metadata, etc.)
    'SSRF_GOPHER_ENABLED': True,              # Allow protocol-smuggling payloads (gopher, dict, file) and Redis/FCGI/Docker RCE chains
    'SSRF_DNS_REBINDING_ENABLED': True,       # Allow DNS-rebinding bypasses via 1u.ms / nip.io / rbndr.us
    'SSRF_PAYLOAD_REFERENCE_ENABLED': True,   # Inject the advanced payload reference + HackerOne precedent tables (~3 KB extra)
    'SSRF_REQUEST_TIMEOUT': 10,               # curl --max-time / --connect-timeout for SSRF probes (seconds)
    'SSRF_PORT_SCAN_PORTS': '22,80,443,2375,3306,5432,6379,8080,8500,9200,27017',  # Comma-separated ports to scan via SSRF
    'SSRF_INTERNAL_RANGES': '127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16',  # Comma-separated CIDR ranges considered internal
    'SSRF_OOB_PROVIDER': 'oast.fun',          # interactsh-client server for OOB callbacks
    'SSRF_CLOUD_PROVIDERS': 'aws,gcp,azure,digitalocean,alibaba',  # Comma-separated cloud providers in scope (filters cloud-metadata section)
    'SSRF_CUSTOM_INTERNAL_TARGETS': '',       # Free-text: site-specific internal hostnames/IPs the agent should prioritize (one per line)

    # RCE / Command Injection Testing
    'RCE_OOB_CALLBACK_ENABLED': True,         # Allow interactsh DNS/HTTP oracle for blind-RCE detection (sends probes via oast.fun)
    'RCE_DESERIALIZATION_ENABLED': True,      # Include the Java/PHP/Python/Ruby deserialization gadget workflow (ysoserial) in the RCE prompt
    'RCE_AGGRESSIVE_PAYLOADS': False,         # If True, permit Step 7: file write, persistent web shells, container/k8s escape probes. Default False = read-only proofs only.

    # Path Traversal / LFI / RFI Testing
    'PATH_TRAVERSAL_OOB_CALLBACK_ENABLED': True,        # Allow interactsh OOB oracle for RFI / blind-LFI detection (sends probes via oast.fun)
    'PATH_TRAVERSAL_PHP_WRAPPERS_ENABLED': True,        # Include PHP-specific wrapper / log-poisoning sub-section (php://filter, data://, expect://, zip://). Trim for non-PHP targets to reduce prompt bloat.
    'PATH_TRAVERSAL_ARCHIVE_EXTRACTION_ENABLED': False, # Allow Zip Slip / TarSlip primitives that WRITE files outside the destination directory. Default False because writing to the target is state-mutating.
    'PATH_TRAVERSAL_PAYLOAD_REFERENCE_ENABLED': True,   # Inject the encoding / bypass / wrapper payload reference (~3 KB extra). Disable for a leaner prompt.
    'PATH_TRAVERSAL_REQUEST_TIMEOUT': 10,               # curl --max-time / --connect-timeout for traversal probes (seconds)
    'PATH_TRAVERSAL_OOB_PROVIDER': 'oast.fun',          # interactsh-client server for RFI / OOB callbacks. Override when oast.fun is blocked.

    # Attack Skill Configuration
    'ATTACK_SKILL_CONFIG': {
        'builtIn': {
            'cve_exploit': True,
            'brute_force_credential_guess': False,
            'phishing_social_engineering': False,
            'denial_of_service': False,
            'sql_injection': True,
            'xss': True,
            'ssrf': True,
            'rce': True,
            'path_traversal': True,
            'access_control': True,
            'http_request_smuggling': True,
            'xxe': True,
            'crypto_attack': True,
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

    response = requests.get(url, headers=INTERNAL_HEADERS, timeout=30)
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
    settings['PLAN_MAX_PARALLEL_TOOLS'] = int(project.get('agentPlanMaxParallelTools', DEFAULT_AGENT_SETTINGS['PLAN_MAX_PARALLEL_TOOLS']))
    settings['CYPHER_MAX_RETRIES'] = project.get('agentCypherMaxRetries', DEFAULT_AGENT_SETTINGS['CYPHER_MAX_RETRIES'])
    settings['LLM_PARSE_MAX_RETRIES'] = project.get('agentLlmParseMaxRetries', DEFAULT_AGENT_SETTINGS['LLM_PARSE_MAX_RETRIES'])
    settings['CREATE_GRAPH_IMAGE_ON_INIT'] = project.get('agentCreateGraphImageOnInit', DEFAULT_AGENT_SETTINGS['CREATE_GRAPH_IMAGE_ON_INIT'])
    settings['LOG_MAX_MB'] = project.get('agentLogMaxMb', DEFAULT_AGENT_SETTINGS['LOG_MAX_MB'])
    settings['LOG_BACKUP_COUNT'] = project.get('agentLogBackupCount', DEFAULT_AGENT_SETTINGS['LOG_BACKUP_COUNT'])
    settings['TOOL_PHASE_MAP'] = project.get('agentToolPhaseMap', DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP'])
    # User-managed MCP servers (UI-driven, see /settings/mcp). The webapp
    # /api/projects/[id] route includes user.settings.mcpServers in its
    # response. Stored here as a raw list of dicts; parse_user_servers()
    # validates and converts to MCPServer instances at orchestrator setup.
    settings['USER_MCP_SERVERS'] = project.get('userMcpServers', []) or []
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
    settings['CAPTURE_PROXY_ENABLED'] = project.get('captureProxyEnabled', DEFAULT_AGENT_SETTINGS['CAPTURE_PROXY_ENABLED'])
    settings['STEALTH_MODE'] = project.get('stealthMode', DEFAULT_AGENT_SETTINGS['STEALTH_MODE'])
    settings['AGENT_GUARDRAIL_ENABLED'] = project.get('agentGuardrailEnabled', DEFAULT_AGENT_SETTINGS['AGENT_GUARDRAIL_ENABLED'])
    # Fireteam (multi-agent)
    settings['FIRETEAM_ENABLED'] = bool(project.get('fireteamEnabled', DEFAULT_AGENT_SETTINGS['FIRETEAM_ENABLED']))
    settings['FIRETEAM_MAX_CONCURRENT'] = int(project.get('fireteamMaxConcurrent', DEFAULT_AGENT_SETTINGS['FIRETEAM_MAX_CONCURRENT']))
    settings['FIRETEAM_MAX_MEMBERS'] = int(project.get('fireteamMaxMembers', DEFAULT_AGENT_SETTINGS['FIRETEAM_MAX_MEMBERS']))
    settings['FIRETEAM_MEMBER_MAX_ITERATIONS'] = int(project.get('fireteamMemberMaxIterations', DEFAULT_AGENT_SETTINGS['FIRETEAM_MEMBER_MAX_ITERATIONS']))
    settings['FIRETEAM_TIMEOUT_SEC'] = int(project.get('fireteamTimeoutSec', DEFAULT_AGENT_SETTINGS['FIRETEAM_TIMEOUT_SEC']))
    settings['FIRETEAM_ALLOWED_PHASES'] = list(project.get('fireteamAllowedPhases', DEFAULT_AGENT_SETTINGS['FIRETEAM_ALLOWED_PHASES']))
    settings['FIRETEAM_CONFIRMATION_TIMEOUT_SEC'] = int(project.get('fireteamConfirmationTimeoutSec', DEFAULT_AGENT_SETTINGS['FIRETEAM_CONFIRMATION_TIMEOUT_SEC']))
    settings['FIRETEAM_PROPENSITY'] = int(project.get('fireteamPropensity', DEFAULT_AGENT_SETTINGS['FIRETEAM_PROPENSITY']))
    # LATS (exploit-path tree search). LATS_ALLOWED_PHASES is assembled from the
    # two phase booleans; the rest map camelCase agentLats* -> LATS_* directly.
    settings['LATS_ENABLED'] = bool(project.get('agentLatsEnabled', DEFAULT_AGENT_SETTINGS['LATS_ENABLED']))
    settings['LATS_SHADOW_MODE'] = bool(project.get('agentLatsShadowMode', DEFAULT_AGENT_SETTINGS['LATS_SHADOW_MODE']))
    _lats_phase_defaults = {'exploitation': True, 'post_exploitation': False}
    _lats_phases = [
        p for p, key in (('exploitation', 'agentLatsPhaseExploitation'),
                         ('post_exploitation', 'agentLatsPhasePostExpl'))
        if bool(project.get(key, _lats_phase_defaults[p]))
    ]
    settings['LATS_ALLOWED_PHASES'] = _lats_phases or list(DEFAULT_AGENT_SETTINGS['LATS_ALLOWED_PHASES'])
    settings['LATS_MIN_HYPOTHESES'] = int(project.get('agentLatsMinHypotheses', DEFAULT_AGENT_SETTINGS['LATS_MIN_HYPOTHESES']))
    settings['LATS_BRANCHING'] = int(project.get('agentLatsBranching', DEFAULT_AGENT_SETTINGS['LATS_BRANCHING']))
    settings['LATS_MAX_DEPTH'] = int(project.get('agentLatsMaxDepth', DEFAULT_AGENT_SETTINGS['LATS_MAX_DEPTH']))
    settings['LATS_MAX_ROLLOUTS'] = int(project.get('agentLatsMaxRollouts', DEFAULT_AGENT_SETTINGS['LATS_MAX_ROLLOUTS']))
    settings['LATS_MAX_TREE_NODES'] = int(project.get('agentLatsMaxTreeNodes', DEFAULT_AGENT_SETTINGS['LATS_MAX_TREE_NODES']))
    settings['LATS_UCT_C'] = float(project.get('agentLatsUctC', DEFAULT_AGENT_SETTINGS['LATS_UCT_C']))
    settings['LATS_PRUNE_FLOOR'] = float(project.get('agentLatsPruneFloor', DEFAULT_AGENT_SETTINGS['LATS_PRUNE_FLOOR']))
    settings['PHISHING_SMTP_CONFIG'] = project.get('phishingSmtpConfig', DEFAULT_AGENT_SETTINGS['PHISHING_SMTP_CONFIG'])
    settings['DOS_MAX_DURATION'] = project.get('dosMaxDuration', DEFAULT_AGENT_SETTINGS['DOS_MAX_DURATION'])
    settings['DOS_MAX_ATTEMPTS'] = project.get('dosMaxAttempts', DEFAULT_AGENT_SETTINGS['DOS_MAX_ATTEMPTS'])
    settings['DOS_CONCURRENT_CONNECTIONS'] = project.get('dosConcurrentConnections', DEFAULT_AGENT_SETTINGS['DOS_CONCURRENT_CONNECTIONS'])
    settings['DOS_ASSESSMENT_ONLY'] = project.get('dosAssessmentOnly', DEFAULT_AGENT_SETTINGS['DOS_ASSESSMENT_ONLY'])
    # SSRF
    settings['SSRF_OOB_CALLBACK_ENABLED'] = project.get('ssrfOobCallbackEnabled', DEFAULT_AGENT_SETTINGS['SSRF_OOB_CALLBACK_ENABLED'])
    settings['SSRF_CLOUD_METADATA_ENABLED'] = project.get('ssrfCloudMetadataEnabled', DEFAULT_AGENT_SETTINGS['SSRF_CLOUD_METADATA_ENABLED'])
    settings['SSRF_GOPHER_ENABLED'] = project.get('ssrfGopherEnabled', DEFAULT_AGENT_SETTINGS['SSRF_GOPHER_ENABLED'])
    settings['SSRF_DNS_REBINDING_ENABLED'] = project.get('ssrfDnsRebindingEnabled', DEFAULT_AGENT_SETTINGS['SSRF_DNS_REBINDING_ENABLED'])
    settings['SSRF_PAYLOAD_REFERENCE_ENABLED'] = project.get('ssrfPayloadReferenceEnabled', DEFAULT_AGENT_SETTINGS['SSRF_PAYLOAD_REFERENCE_ENABLED'])
    settings['SSRF_REQUEST_TIMEOUT'] = project.get('ssrfRequestTimeout', DEFAULT_AGENT_SETTINGS['SSRF_REQUEST_TIMEOUT'])
    settings['SSRF_PORT_SCAN_PORTS'] = project.get('ssrfPortScanPorts', DEFAULT_AGENT_SETTINGS['SSRF_PORT_SCAN_PORTS'])
    settings['SSRF_INTERNAL_RANGES'] = project.get('ssrfInternalRanges', DEFAULT_AGENT_SETTINGS['SSRF_INTERNAL_RANGES'])
    settings['SSRF_OOB_PROVIDER'] = project.get('ssrfOobProvider', DEFAULT_AGENT_SETTINGS['SSRF_OOB_PROVIDER'])
    settings['SSRF_CLOUD_PROVIDERS'] = project.get('ssrfCloudProviders', DEFAULT_AGENT_SETTINGS['SSRF_CLOUD_PROVIDERS'])
    settings['SSRF_CUSTOM_INTERNAL_TARGETS'] = project.get('ssrfCustomInternalTargets', DEFAULT_AGENT_SETTINGS['SSRF_CUSTOM_INTERNAL_TARGETS'])
    # RCE
    settings['RCE_OOB_CALLBACK_ENABLED'] = project.get('rceOobCallbackEnabled', DEFAULT_AGENT_SETTINGS['RCE_OOB_CALLBACK_ENABLED'])
    settings['RCE_DESERIALIZATION_ENABLED'] = project.get('rceDeserializationEnabled', DEFAULT_AGENT_SETTINGS['RCE_DESERIALIZATION_ENABLED'])
    settings['RCE_AGGRESSIVE_PAYLOADS'] = project.get('rceAggressivePayloads', DEFAULT_AGENT_SETTINGS['RCE_AGGRESSIVE_PAYLOADS'])
    # Path Traversal / LFI / RFI
    settings['PATH_TRAVERSAL_OOB_CALLBACK_ENABLED'] = project.get('pathTraversalOobCallbackEnabled', DEFAULT_AGENT_SETTINGS['PATH_TRAVERSAL_OOB_CALLBACK_ENABLED'])
    settings['PATH_TRAVERSAL_PHP_WRAPPERS_ENABLED'] = project.get('pathTraversalPhpWrappersEnabled', DEFAULT_AGENT_SETTINGS['PATH_TRAVERSAL_PHP_WRAPPERS_ENABLED'])
    settings['PATH_TRAVERSAL_ARCHIVE_EXTRACTION_ENABLED'] = project.get('pathTraversalArchiveExtractionEnabled', DEFAULT_AGENT_SETTINGS['PATH_TRAVERSAL_ARCHIVE_EXTRACTION_ENABLED'])
    settings['PATH_TRAVERSAL_PAYLOAD_REFERENCE_ENABLED'] = project.get('pathTraversalPayloadReferenceEnabled', DEFAULT_AGENT_SETTINGS['PATH_TRAVERSAL_PAYLOAD_REFERENCE_ENABLED'])
    settings['PATH_TRAVERSAL_REQUEST_TIMEOUT'] = project.get('pathTraversalRequestTimeout', DEFAULT_AGENT_SETTINGS['PATH_TRAVERSAL_REQUEST_TIMEOUT'])
    settings['PATH_TRAVERSAL_OOB_PROVIDER'] = project.get('pathTraversalOobProvider', DEFAULT_AGENT_SETTINGS['PATH_TRAVERSAL_OOB_PROVIDER'])
    settings['ATTACK_SKILL_CONFIG'] = project.get('attackSkillConfig', DEFAULT_AGENT_SETTINGS['ATTACK_SKILL_CONFIG'])
    settings['USER_ATTACK_SKILLS'] = project.get('userAttackSkills', DEFAULT_AGENT_SETTINGS['USER_ATTACK_SKILLS'])

    # Target scope (used by guardrail checks inside the agent)
    settings['TARGET_DOMAIN'] = project.get('targetDomain', '')
    settings['IP_MODE'] = project.get('ipMode', False)
    settings['TARGET_IPS'] = project.get('targetIps', [])
    # Domain batch has an EMPTY targetDomain: its scope is the derived group roots.
    # Without these two the agent's guardrails see no target at all and skip
    # themselves, which is the opposite of fail-closed. See target_scope_domains().
    settings['DOMAIN_BATCH_MODE'] = project.get('domainBatchMode', False)
    settings['DOMAIN_BATCH_GROUPS'] = project.get('domainBatchGroups') or []

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
                headers=INTERNAL_HEADERS,
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
                headers=INTERNAL_HEADERS,
                timeout=10,
            )
            user_settings_resp.raise_for_status()
            settings['USER_SETTINGS'] = user_settings_resp.json()
        except Exception as e:
            logger.warning(f"Failed to fetch user settings: {e}")
            settings['USER_SETTINGS'] = {}

        # Fetch user tradecraft resources (for the tradecraft_lookup tool catalog)
        try:
            tc_resp = requests.get(
                f"{webapp_url.rstrip('/')}/api/users/{user_id}/tradecraft-resources?internal=true",
                headers=INTERNAL_HEADERS,
                timeout=10,
            )
            tc_resp.raise_for_status()
            settings['TRADECRAFT_RESOURCES'] = tc_resp.json()
        except Exception as e:
            logger.warning(f"Failed to fetch tradecraft resources: {e}")
            settings['TRADECRAFT_RESOURCES'] = []

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

    Resolution order (concurrency-safe):
      1. The per-task ContextVar `_settings_ctx`, set by load_project_settings()
         inside each session's own asyncio task. This isolates concurrent
         sessions for different projects so they never read each other's values.
      2. The module-global `_settings` (last-loaded snapshot). This is the
         fallback for readers OUTSIDE a session task - HTTP endpoints
         (/api/roe/parse, /api/report/summarize), /health, and tests that set
         `_settings` directly - preserving the pre-ContextVar behavior for them.
      3. Memory-governed DEFAULT_AGENT_SETTINGS until any project is loaded.

    Use load_project_settings() to fetch settings for a specific project.
    """
    ctx = _settings_ctx.get()
    if ctx is not None:
        return ctx
    global _settings
    if _settings is not None:
        return _settings
    # Return defaults until a project is loaded (governed too, so any early
    # consumer still gets memory-scaled concurrency; fresh copy -> no compounding).
    logger.info("Using DEFAULT_AGENT_SETTINGS (no project loaded yet)")
    return apply_memory_governor(DEFAULT_AGENT_SETTINGS.copy())


# Per-task settings binding: the PRIMARY source. Each concurrent session runs in
# its own asyncio task; load_project_settings() sets this so a task always reads
# its OWN project's settings regardless of what other concurrent sessions load.
# (asyncio copies the context at task creation, so fireteam member sub-tasks
# spawned after the load inherit the correct snapshot automatically.)
_settings_ctx: contextvars.ContextVar[Optional[dict[str, Any]]] = contextvars.ContextVar(
    "agent_settings", default=None
)

# Module-global FALLBACK (last-loaded snapshot). Used only by readers running
# outside a session task, and by tests that assign `_settings`/`_current_project_id`
# directly. Not the primary source while a session task is active.
_settings: Optional[dict[str, Any]] = None
_current_project_id: Optional[str] = None


# =============================================================================
# Memory governor (Part 3): BYTE-BUDGET the agent's CONCURRENCY knobs to the RAM
# available when the turn starts. Each concurrent fireteam member (~512MB) and
# plan-tool slot (~400MB) costs absolute megabytes, so ratio-scaling is wrong on
# small hosts (2GB free on a 4GB host is ratio 0.5 -> no throttle -> OOM). The
# byte-budget (available x fraction / envelope) caps by what actually fits; a
# generous 0.5 fraction keeps the full value at reasonable RAM and throttles hard
# only when memory is genuinely scarce.
#
# We scale CONCURRENCY (how many run at once), NOT FIRETEAM_MAX_MEMBERS (how many
# a plan contains) — scaling membership would silently truncate a coordinated
# plan across a resume. Reducing concurrency serializes members safely instead.
#
# Applied per turn via load_project_settings (fresh dict -> no compounding). NOTE:
# this samples RAM at turn START, not per node; the agent/kali container mem_limits
# (Part 4) backstop pressure that develops mid-run. Emits [RESOURCE-CAP] logs.
# Fail-open.
# =============================================================================
_AGENT_BUDGET_KEYS = {
    'FIRETEAM_MAX_CONCURRENT': ('fireteam_member_envelope_bytes', 1),
    'PLAN_MAX_PARALLEL_TOOLS': ('plan_tool_slot_envelope_bytes', 1),
}


def apply_memory_governor(settings: dict[str, Any]) -> dict[str, Any]:
    """Byte-budget agent concurrency keys to available RAM. Pure; fail-open."""
    try:
        from graph_db import resource_governor as rg
    except Exception:
        try:
            import resource_governor as rg   # direct (tests / alt path)
        except Exception:
            return settings
    try:
        if not rg.governor_enabled():
            return settings
        frac = rg._env_float('AGENT_MEM_BUDGET_FRACTION', 0.5)
    except Exception:
        return settings

    for key, (env_key, floor) in _AGENT_BUDGET_KEYS.items():
        val = settings.get(key)
        if isinstance(val, int) and not isinstance(val, bool) and val > 0:
            try:
                env = rg.envelope(env_key)
                eff = rg.scaled_cap(val, env, frac, floor)
            except Exception:
                continue
            if eff < val:
                tool = 'fireteam' if key.startswith('FIRETEAM') else 'plan'
                rg.log_cap(tool, key, val, eff, 'byte-budget')
                settings[key] = eff
    return settings


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
        settings = DEFAULT_AGENT_SETTINGS.copy()
    else:
        try:
            settings = fetch_agent_settings(project_id, webapp_url)
            logger.info(f"Loaded {len(settings)} agent settings from API for project {project_id}")
        except Exception as e:
            logger.error(f"Failed to fetch agent settings for project {project_id}: {e}")
            logger.warning("Falling back to DEFAULT_AGENT_SETTINGS")
            settings = DEFAULT_AGENT_SETTINGS.copy()

    # Memory governor (Part 3): scale concurrency to RAM available this turn.
    settings = apply_memory_governor(settings)

    # PRIMARY: bind to this asyncio task so concurrent sessions stay isolated.
    _settings_ctx.set(settings)
    # FALLBACK: last-loaded snapshot for out-of-task readers + test compatibility.
    _settings = settings
    _current_project_id = project_id
    return settings


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


_SCOPE_DOMAIN_CHARSET = re.compile(r'^[a-z0-9.-]+$')


def target_scope_domains() -> list[str]:
    """Every domain this project is authorized to touch, whatever its target mode.

    Both agent guardrails used to read TARGET_DOMAIN alone. A Domain-batch project
    leaves that empty and keeps its scope in DOMAIN_BATCH_GROUPS, so the soft
    guardrail returned early ("nothing to check") and the hard guardrail's
    `if not ip_mode and target_domain` was false: BOTH silently disarmed on exactly
    the projects with the most targets. This is the single source of scope for them.

    Returns [] only for a genuinely unconfigured project or IP mode. Callers must
    treat an EMPTY list in batch mode as a refusal, never as "nothing to check".
    """
    if get_setting('IP_MODE', False):
        return []

    if get_setting('DOMAIN_BATCH_MODE', False):
        groups = get_setting('DOMAIN_BATCH_GROUPS', []) or []
        roots: list[str] = []
        if isinstance(groups, list):
            for entry in groups:
                if not isinstance(entry, dict):
                    continue
                root = str(entry.get('rootDomain') or '').strip().lower()
                # Same charset rule as the recon and orchestrator parsers: drop
                # rather than repair, so a hand-edited row cannot smuggle a target.
                if root and _SCOPE_DOMAIN_CHARSET.match(root) and '..' not in root:
                    if root not in roots:
                        roots.append(root)
        return roots

    domain = (get_setting('TARGET_DOMAIN', '') or '').strip()
    return [domain] if domain else []


def reload_settings(project_id: Optional[str] = None) -> dict[str, Any]:
    """Force reload of settings for a project."""
    global _settings, _current_project_id
    if project_id:
        _current_project_id = None  # Force refetch
        return load_project_settings(project_id)
    _settings = None
    _current_project_id = None
    _settings_ctx.set(None)
    return get_settings()


# =============================================================================
# ATTACK SKILL HELPERS
# =============================================================================

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


# =============================================================================
# TOOL PHASE RESTRICTION HELPERS (moved from params.py)
# =============================================================================

def is_tool_allowed_in_phase(tool_name: str, phase: str) -> bool:
    """Check if a tool is allowed in the given phase.

    Resolution order:
    1. Foundational fs_*/job_* tools: always allowed (phase-agnostic, like query_graph).
    2. Project's TOOL_PHASE_MAP override (per-project, per-tool, set via UI).
    3. MCP manifest default_phases (for tools declared by user-managed MCP servers).
    4. Default to all phases (when nothing else specifies).
    """
    # fs_* (workspace filesystem) and job_* (background runner) are infrastructure
    # tools - blocking them by phase makes no sense. They cannot reach the network
    # or run scans on their own; only what runs through them is phase-relevant.
    if tool_name.startswith("fs_") or tool_name.startswith("job_"):
        return True

    tool_phase_map = get_setting('TOOL_PHASE_MAP', {})
    if tool_name in tool_phase_map:
        return phase in tool_phase_map[tool_name]

    # Fallback to MCP manifest default phases
    try:
        from mcp_registry import default_phases_for, manifest_tool_names
        if tool_name in manifest_tool_names():
            return phase in default_phases_for(tool_name)
    except Exception:
        pass

    return False


def get_allowed_tools_for_phase(phase: str) -> list:
    """Get list of tool names allowed in the given phase.

    Includes both TOOL_PHASE_MAP entries and MCP-manifest-declared tools whose
    effective default phases include ``phase``. Always includes foundational
    fs_*/job_* tools (Phase-2 bypass also lives in is_tool_allowed_in_phase).

    BUG #20 regression: this function previously returned only TOOL_PHASE_MAP +
    manifest tools, omitting the foundational fs_*/job_* set entirely. The
    LLM's available-tools enum is built from this list - so the agent never
    saw fs_mkdir / fs_write / job_spawn / etc. and fell back to
    `kali_shell "mkdir -p"` for filesystem ops, defeating the whole point of
    the in-process workspace tools.
    """
    tool_phase_map = get_setting('TOOL_PHASE_MAP', {})
    allowed = {
        tool_name
        for tool_name, allowed_phases in tool_phase_map.items()
        if phase in allowed_phases
    }

    # Always include foundational workspace + job tools (mirror of the
    # fs_/job_ bypass in is_tool_allowed_in_phase). Import lazily to keep
    # this module heavyweight-dep free.
    try:
        from workspace_fs import FS_TOOL_NAMES
        from job_runner import JOB_TOOL_NAMES
        allowed.update(FS_TOOL_NAMES)
        allowed.update(JOB_TOOL_NAMES)
    except Exception:
        pass

    # Union with manifest-declared tools that allow this phase by default
    try:
        from mcp_registry import manifest_tool_phase_view
        for tool_name, default_phases in manifest_tool_phase_view().items():
            if tool_name in tool_phase_map:
                continue  # project override wins
            if phase in default_phases:
                allowed.add(tool_name)
    except Exception:
        pass

    return list(allowed)


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

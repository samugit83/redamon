"""
RedAmon Agent Prompts Package

System prompts for the ReAct agent orchestrator.
Includes phase-aware reasoning, tool descriptions, and structured output formats.
"""

# Re-export from base
from .base import (
    TOOL_REGISTRY,
    MODE_DECISION_MATRIX,
    REACT_SYSTEM_PROMPT,
    PENDING_OUTPUT_ANALYSIS_SECTION,
    PENDING_PLAN_OUTPUTS_SECTION,
    RESPONSE_CLASS_TAXONOMY_BLOCK,
    PHASE_TRANSITION_MESSAGE,
    USER_QUESTION_MESSAGE,
    FINAL_REPORT_PROMPT,
    CONVERSATIONAL_RESPONSE_PROMPT,
    SUMMARY_RESPONSE_PROMPT,
    determine_response_tier,
    TEXT_TO_CYPHER_SYSTEM,
    # Dynamic prompt builders
    build_tool_availability_table,
    build_informational_tool_descriptions,
    build_compact_tool_list,
    build_informational_guidance,
    build_attack_path_behavior,
    build_tool_args_section,
    build_tool_name_enum,
    build_phase_definitions,
    build_kali_install_prompt,
    DEEP_THINK_PROMPT,
    DEEP_THINK_SECTION,
    DEEP_THINK_SELF_REQUEST_INSTRUCTION,
)

# Re-export from classification
from .classification import ATTACK_PATH_CLASSIFICATION_PROMPT, build_classification_prompt

# Re-export from CVE exploit prompts
from .cve_exploit_prompts import (
    CVE_EXPLOIT_TOOLS,
    CVE_PAYLOAD_GUIDANCE_STATEFULL,
    CVE_PAYLOAD_GUIDANCE_STATELESS,
    NO_MODULE_FALLBACK_STATEFULL,
    NO_MODULE_FALLBACK_STATELESS,
)

# Re-export from Hydra brute force prompts
from .brute_force_credential_guess_prompts import (
    HYDRA_BRUTE_FORCE_TOOLS,
    HYDRA_WORDLIST_GUIDANCE,
)

# Re-export from phishing / social engineering prompts
from .phishing_social_engineering_prompts import (
    PHISHING_SOCIAL_ENGINEERING_TOOLS,
    PHISHING_PAYLOAD_FORMAT_GUIDANCE,
)

# Re-export from denial of service prompts
from .denial_of_service_prompts import (
    DOS_TOOLS,
    DOS_VECTOR_SELECTION,
    DOS_VERIFICATION_GUIDE,
)

# Re-export from SQL injection prompts
from .sql_injection_prompts import (
    SQLI_TOOLS,
    SQLI_OOB_WORKFLOW,
    SQLI_PAYLOAD_REFERENCE,
)

# Re-export from XSS prompts
from .xss_prompts import (
    XSS_TOOLS,
    XSS_BLIND_WORKFLOW,
    XSS_PAYLOAD_REFERENCE,
)

# Re-export from SSRF prompts
from .ssrf_prompts import (
    SSRF_TOOLS,
    SSRF_OOB_WORKFLOW,
    SSRF_GOPHER_CHAINS,
    SSRF_DNS_REBINDING,
    SSRF_PAYLOAD_REFERENCE,
    SSRF_CLOUD_PROVIDER_BLOCKS,
    SSRF_CLOUD_DISABLED_STUB,
)

# Re-export from RCE prompts
from .rce_prompts import (
    RCE_TOOLS,
    RCE_AGGRESSIVE_DISABLED,
    RCE_AGGRESSIVE_ENABLED,
    RCE_OOB_WORKFLOW,
    RCE_DESERIALIZATION_WORKFLOW,
    RCE_PAYLOAD_REFERENCE,
)

# Re-export from Path Traversal / LFI / RFI prompts
from .path_traversal_prompts import (
    PATH_TRAVERSAL_TOOLS,
    PATH_TRAVERSAL_PHP_WRAPPERS,
    PATH_TRAVERSAL_OOB_WORKFLOW,
    PATH_TRAVERSAL_ARCHIVE_EXTRACTION,
    PATH_TRAVERSAL_PAYLOAD_REFERENCE,
)

# Re-export from HTTP request smuggling prompts
from .http_smuggling_prompts import HTTP_SMUGGLING_TOOLS

# Re-export from XML External Entity (XXE) injection prompts
from .xxe_prompts import XXE_TOOLS
from .crypto_attack_prompts import CRYPTO_ATTACK_TOOLS

# Re-export from unclassified attack path prompts
from .unclassified_prompts import UNCLASSIFIED_EXPLOIT_TOOLS

# Re-export from Broken Access Control / Authorization Bypass prompts
from .access_control_prompts import ACCESS_CONTROL_TOOLS

# Re-export from post-exploitation prompts
from .post_exploitation import (
    POST_EXPLOITATION_TOOLS_STATEFULL,
    POST_EXPLOITATION_TOOLS_STATELESS,
)

# Re-export from stealth rules
from .stealth_rules import STEALTH_MODE_RULES

# Import utilities
from utils import get_session_config_prompt
from project_settings import get_setting, get_allowed_tools_for_phase, get_hydra_flags_from_settings, get_dos_settings_dict


def _msf_search_failed(execution_trace: list) -> bool:
    """Check if a Metasploit `search` command returned no results in the trace."""
    for step in execution_trace:
        if step.get("tool_name") != "metasploit_console":
            continue
        output = step.get("tool_output") or ""
        args = step.get("tool_args") or {}
        command = args.get("command", "") if isinstance(args, dict) else str(args)
        # Only match actual search commands, not other msf commands
        if "search " in command.lower() and (
            "No results" in output
            or "0 results" in output
            or "did not match" in output.lower()
        ):
            return True
    return False


def build_builtin_skill_workflow(
    attack_path_type: str,
    allowed_tools,
    is_statefull: bool = False,
    execution_trace: list = None,
) -> list:
    """Build the built-in skill workflow prompt parts for an attack path.

    Returns the list of workflow strings (payload playbook, OOB/deser sub-
    workflows, payload reference) for the active attack_path_type when it
    matches an enabled built-in skill and its required tools are allowed;
    an empty list otherwise. Single source of truth shared by get_phase_tools
    (full think-node prompt) and LATS expand (grounded probe proposal), so the
    two never drift on which technique playbook a class gets.
    """
    parts = []
    from project_settings import get_enabled_builtin_skills
    enabled_builtins = get_enabled_builtin_skills()

    if (attack_path_type == "brute_force_credential_guess"
            and "brute_force_credential_guess" in enabled_builtins
            and "execute_hydra" in allowed_tools
            and not (get_setting('ROE_ENABLED', False) and not get_setting('ROE_ALLOW_ACCOUNT_LOCKOUT', False))):
        # Hydra-based brute force workflow
        hydra_flags = get_hydra_flags_from_settings()
        import re as _re
        hydra_flags_no_t = _re.sub(r'-t\s+\d+\s*', '', hydra_flags).strip()
        parts.append(HYDRA_BRUTE_FORCE_TOOLS.format(
            hydra_max_attempts=get_setting('HYDRA_MAX_WORDLIST_ATTEMPTS', 3),
            hydra_flags=hydra_flags,
            hydra_flags_no_t=hydra_flags_no_t
        ))
        parts.append(HYDRA_WORDLIST_GUIDANCE)
        return parts
    elif (attack_path_type == "phishing_social_engineering"
            and "phishing_social_engineering" in enabled_builtins
            and not (get_setting('ROE_ENABLED', False) and not get_setting('ROE_ALLOW_SOCIAL_ENGINEERING', False))):
        parts.append(PHISHING_SOCIAL_ENGINEERING_TOOLS)
        parts.append(PHISHING_PAYLOAD_FORMAT_GUIDANCE)
        smtp_config = get_setting('PHISHING_SMTP_CONFIG', '')
        if smtp_config:
            parts.append(
                f"## Pre-Configured SMTP Settings\n\n"
                f"Use these for email delivery via execute_code (Python smtplib):\n{smtp_config}\n"
            )
        return parts
    elif (attack_path_type == "denial_of_service"
            and "denial_of_service" in enabled_builtins
            and not (get_setting('ROE_ENABLED', False) and not get_setting('ROE_ALLOW_DOS', False))):
        dos_settings = get_dos_settings_dict()
        assessment_only = get_setting('DOS_ASSESSMENT_ONLY', False)
        dos_assessment_block = (
            "\n## ASSESSMENT ONLY MODE (ACTIVE)\n"
            "You are in ASSESSMENT-ONLY mode. Do NOT execute any DoS attack.\n"
            "Only research and report whether the target is VULNERABLE to DoS:\n"
            "- Run nmap DoS scripts appropriate to the OPEN services (`--script dos`; add\n"
            "  service-specific checks like `rdp-ms12-020` ONLY when that service, e.g. RDP/3389, is actually present)\n"
            "- Run nuclei -tags dos\n"
            "- Research known DoS CVEs for detected service versions\n"
            '- Report findings with action="complete"\n'
        ) if assessment_only else ""
        parts.append(DOS_TOOLS.format(
            **dos_settings,
            dos_assessment_only_block=dos_assessment_block,
        ))
        parts.append(DOS_VECTOR_SELECTION.format(**dos_settings))
        parts.append(DOS_VERIFICATION_GUIDE)
        return parts
    elif (attack_path_type == "sql_injection"
            and "sql_injection" in enabled_builtins
            and "kali_shell" in allowed_tools):
        sqli_settings = {
            'sqli_level': get_setting('SQLI_LEVEL', 1),
            'sqli_risk': get_setting('SQLI_RISK', 1),
            'sqli_tamper_scripts': get_setting('SQLI_TAMPER_SCRIPTS', '') or 'none configured',
        }
        parts.append(SQLI_TOOLS.format(**sqli_settings))
        parts.append(SQLI_OOB_WORKFLOW)
        parts.append(SQLI_PAYLOAD_REFERENCE)
        return parts
    elif (attack_path_type == "xss"
            and "xss" in enabled_builtins
            and "execute_curl" in allowed_tools):
        xss_settings = {
            'xss_dalfox_enabled': get_setting('XSS_DALFOX_ENABLED', True),
            'xss_blind_callback_enabled': get_setting('XSS_BLIND_CALLBACK_ENABLED', False),
            'xss_csp_bypass_enabled': get_setting('XSS_CSP_BYPASS_ENABLED', True),
        }
        parts.append(XSS_TOOLS.format(**xss_settings))
        if xss_settings['xss_blind_callback_enabled'] and "kali_shell" in allowed_tools:
            parts.append(XSS_BLIND_WORKFLOW)
        parts.append(XSS_PAYLOAD_REFERENCE)
        return parts
    elif (attack_path_type == "ssrf"
            and "ssrf" in enabled_builtins
            and "execute_curl" in allowed_tools):
        ssrf_oob_enabled = get_setting('SSRF_OOB_CALLBACK_ENABLED', True)
        ssrf_cloud_enabled = get_setting('SSRF_CLOUD_METADATA_ENABLED', True)
        ssrf_gopher_enabled = get_setting('SSRF_GOPHER_ENABLED', True)
        ssrf_rebind_enabled = get_setting('SSRF_DNS_REBINDING_ENABLED', True)
        ssrf_payref_enabled = get_setting('SSRF_PAYLOAD_REFERENCE_ENABLED', True)

        # Build cloud section: filter SSRF_CLOUD_PROVIDER_BLOCKS by enabled
        # providers if cloud-metadata is on, else inject the disabled stub.
        if ssrf_cloud_enabled:
            providers_csv = get_setting('SSRF_CLOUD_PROVIDERS', 'aws,gcp,azure,digitalocean,alibaba')
            requested = [p.strip().lower() for p in providers_csv.split(',') if p.strip()]
            cloud_blocks = [SSRF_CLOUD_PROVIDER_BLOCKS[p] for p in requested if p in SSRF_CLOUD_PROVIDER_BLOCKS]
            ssrf_cloud_section = "\n".join(cloud_blocks) if cloud_blocks else SSRF_CLOUD_DISABLED_STUB
        else:
            ssrf_cloud_section = SSRF_CLOUD_DISABLED_STUB

        # Build custom-targets section from free-text setting
        custom_targets = (get_setting('SSRF_CUSTOM_INTERNAL_TARGETS', '') or '').strip()
        if custom_targets:
            ssrf_custom_targets_section = (
                "## SITE-SPECIFIC INTERNAL TARGETS\n\n"
                "The operator has flagged these internal hosts/IPs for prioritized probing:\n\n"
                f"```\n{custom_targets}\n```\n\n"
                "Probe these alongside the generic loopback / RFC1918 sweep in Step 3."
            )
        else:
            ssrf_custom_targets_section = ""

        ssrf_settings = {
            'ssrf_oob_callback_enabled': ssrf_oob_enabled,
            'ssrf_cloud_metadata_enabled': ssrf_cloud_enabled,
            'ssrf_gopher_enabled': ssrf_gopher_enabled,
            'ssrf_dns_rebinding_enabled': ssrf_rebind_enabled,
            'ssrf_payload_reference_enabled': ssrf_payref_enabled,
            'ssrf_request_timeout': get_setting('SSRF_REQUEST_TIMEOUT', 10),
            'ssrf_port_scan_ports': get_setting('SSRF_PORT_SCAN_PORTS',
                '22,80,443,2375,3306,5432,6379,8080,8500,9200,27017'),
            'ssrf_internal_ranges': get_setting('SSRF_INTERNAL_RANGES',
                '127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16'),
            'ssrf_oob_provider': get_setting('SSRF_OOB_PROVIDER', 'oast.fun'),
            'ssrf_cloud_providers': get_setting('SSRF_CLOUD_PROVIDERS',
                'aws,gcp,azure,digitalocean,alibaba') if ssrf_cloud_enabled else 'disabled',
            'ssrf_cloud_section': ssrf_cloud_section,
            'ssrf_custom_targets_section': ssrf_custom_targets_section,
        }
        parts.append(SSRF_TOOLS.format(**ssrf_settings))
        if ssrf_oob_enabled and "kali_shell" in allowed_tools:
            parts.append(SSRF_OOB_WORKFLOW)
        if ssrf_gopher_enabled:
            parts.append(SSRF_GOPHER_CHAINS)
        if ssrf_rebind_enabled:
            parts.append(SSRF_DNS_REBINDING)
        if ssrf_payref_enabled:
            parts.append(SSRF_PAYLOAD_REFERENCE)
        return parts
    elif (attack_path_type == "path_traversal"
            and "path_traversal" in enabled_builtins
            and "execute_curl" in allowed_tools):
        pt_oob_enabled = get_setting('PATH_TRAVERSAL_OOB_CALLBACK_ENABLED', True)
        pt_php_enabled = get_setting('PATH_TRAVERSAL_PHP_WRAPPERS_ENABLED', True)
        pt_archive_enabled = get_setting('PATH_TRAVERSAL_ARCHIVE_EXTRACTION_ENABLED', False)
        pt_payref_enabled = get_setting('PATH_TRAVERSAL_PAYLOAD_REFERENCE_ENABLED', True)
        pt_settings = {
            'path_traversal_oob_callback_enabled': pt_oob_enabled,
            'path_traversal_php_wrappers_enabled': pt_php_enabled,
            'path_traversal_archive_extraction_enabled': pt_archive_enabled,
            'path_traversal_payload_reference_enabled': pt_payref_enabled,
            'path_traversal_request_timeout': get_setting('PATH_TRAVERSAL_REQUEST_TIMEOUT', 10),
            'path_traversal_oob_provider': get_setting('PATH_TRAVERSAL_OOB_PROVIDER', 'oast.fun'),
        }
        parts.append(PATH_TRAVERSAL_TOOLS.format(**pt_settings))
        if pt_php_enabled:
            parts.append(PATH_TRAVERSAL_PHP_WRAPPERS)
        if pt_oob_enabled and "kali_shell" in allowed_tools:
            parts.append(PATH_TRAVERSAL_OOB_WORKFLOW)
        if pt_archive_enabled and "execute_code" in allowed_tools:
            parts.append(PATH_TRAVERSAL_ARCHIVE_EXTRACTION)
        if pt_payref_enabled:
            parts.append(PATH_TRAVERSAL_PAYLOAD_REFERENCE)
        return parts
    elif (attack_path_type == "rce"
            and "rce" in enabled_builtins
            and "kali_shell" in allowed_tools):
        rce_oob_enabled = get_setting('RCE_OOB_CALLBACK_ENABLED', True)
        rce_deser_enabled = get_setting('RCE_DESERIALIZATION_ENABLED', True)
        rce_aggressive = get_setting('RCE_AGGRESSIVE_PAYLOADS', False)
        rce_aggressive_block = RCE_AGGRESSIVE_ENABLED if rce_aggressive else RCE_AGGRESSIVE_DISABLED
        rce_settings = {
            'rce_oob_callback_enabled': rce_oob_enabled,
            'rce_deserialization_enabled': rce_deser_enabled,
            'rce_aggressive_payloads': rce_aggressive,
            'rce_aggressive_block': rce_aggressive_block,
        }
        parts.append(RCE_TOOLS.format(**rce_settings))
        if rce_oob_enabled:
            parts.append(RCE_OOB_WORKFLOW)
        if rce_deser_enabled:
            parts.append(RCE_DESERIALIZATION_WORKFLOW)
        parts.append(RCE_PAYLOAD_REFERENCE)
        return parts
    elif ("cve_exploit" == attack_path_type
            and "cve_exploit" in enabled_builtins
            and "metasploit_console" in allowed_tools):
        parts.append(CVE_EXPLOIT_TOOLS)
        payload_guidance = CVE_PAYLOAD_GUIDANCE_STATEFULL if is_statefull else CVE_PAYLOAD_GUIDANCE_STATELESS
        parts.append(payload_guidance)
        if _msf_search_failed(execution_trace or []):
            if is_statefull:
                parts.append(NO_MODULE_FALLBACK_STATEFULL)
            else:
                parts.append(NO_MODULE_FALLBACK_STATELESS)
        return parts
    elif (attack_path_type == "access_control"
            and "access_control" in enabled_builtins
            and "execute_curl" in allowed_tools):
        parts.append(ACCESS_CONTROL_TOOLS)
        return parts
    elif (attack_path_type == "http_request_smuggling"
            and "http_request_smuggling" in enabled_builtins
            and "execute_code" in allowed_tools):
        parts.append(HTTP_SMUGGLING_TOOLS)
        return parts
    elif (attack_path_type == "xxe"
            and "xxe" in enabled_builtins
            and "execute_curl" in allowed_tools):
        parts.append(XXE_TOOLS)
        return parts
    elif (attack_path_type == "crypto_attack"
            and "crypto_attack" in enabled_builtins
            and "execute_code" in allowed_tools):
        parts.append(CRYPTO_ATTACK_TOOLS)
        return parts
    return parts


def get_phase_tools(
    phase: str,
    activate_post_expl: bool = True,
    post_expl_type: str = "stateless",
    attack_path_type: str = "",
    execution_trace: list = None,
    tool_filter: set = None,
) -> str:
    """Get tool descriptions for the current phase with attack path-specific guidance.

    All tool references are dynamically filtered based on the DB TOOL_PHASE_MAP,
    so the LLM only sees tools that are actually allowed in the current phase.

    Args:
        phase: Current agent phase (informational, exploitation, post_exploitation)
        activate_post_expl: If True, post-exploitation phase is available.
                           If False, exploitation is the final phase.
        post_expl_type: "statefull" for Meterpreter sessions, "stateless" for single commands.
        attack_path_type: Type of attack path ("cve_exploit", "brute_force_credential_guess", "phishing_social_engineering", "denial_of_service", "sql_injection")
        execution_trace: List of execution steps (used to detect MSF search failures).
        tool_filter: Optional whitelist of tool names. When set, the rendered output is
                     restricted to the intersection of phase-allowed tools and this set.
                     Used by fireteam members to render a "primary tools" view limited
                     to their declared skills. None means no filtering (full phase view).

    Returns:
        Concatenated tool descriptions appropriate for the phase, mode, and attack path.
    """
    parts = []
    is_statefull = post_expl_type == "statefull"

    # Stealth mode header — reminds LLM that stealth constraints apply to all tools below
    if get_setting('STEALTH_MODE', False):
        parts.append(
            "## STEALTH MODE ACTIVE\n\n"
            "All tools below MUST be used with stealth constraints. "
            "See STEALTH MODE rules above for per-tool restrictions.\n"
        )

    # Add phase-specific custom system prompt if configured
    informational_prompt = get_setting('INFORMATIONAL_SYSTEM_PROMPT', '')
    expl_prompt = get_setting('EXPL_SYSTEM_PROMPT', '')
    post_expl_prompt = get_setting('POST_EXPL_SYSTEM_PROMPT', '')

    if phase == "informational" and informational_prompt:
        parts.append(f"## Custom Instructions\n\n{informational_prompt}\n")
    elif phase == "exploitation" and expl_prompt:
        parts.append(f"## Custom Instructions\n\n{expl_prompt}\n")
    elif phase == "post_exploitation" and post_expl_prompt:
        parts.append(f"## Custom Instructions\n\n{post_expl_prompt}\n")

    # Determine allowed tools for current phase (dynamic from TOOL_PHASE_MAP in DB)
    phase_allowed_unfiltered = get_allowed_tools_for_phase(phase)
    # Optional fireteam-member filter: render only the intersection with the
    # member's declared skills, so the "primary tools" view stays focused.
    # Phase-allowlisting still applies — filter is a SUBSET operation, never a
    # superset.
    if tool_filter is not None:
        allowed_tools = [t for t in phase_allowed_unfiltered if t in tool_filter]
    else:
        allowed_tools = phase_allowed_unfiltered

    # Kali shell library installation rules (prompt-based control).
    # IMPORTANT: check the UNFILTERED phase allowlist. A fireteam member may
    # render the "primary tools" view without kali_shell in its declared
    # skills, but kali_shell still appears in the member's fallback toolbox
    # and is callable. The install constraints must be communicated regardless
    # of which view we're rendering — otherwise the model may try `apt install`
    # via a fallback kali_shell call without seeing the warning.
    if "kali_shell" in phase_allowed_unfiltered:
        parts.append(build_kali_install_prompt())

    # Dynamic tool availability table — render in EVERY phase so the LLM
    # always sees the same purpose + when_to_use columns for any allowed
    # tool. Phase toggles control whether a tool appears at all (via
    # allowed_tools), not which fields render.
    #
    # When a tool_filter is active (fireteam member primary view), suppress
    # the "Current phase allows: ..." summary line — the filtered list is
    # NOT what the phase fully allows, and emitting it as such would lie to
    # the model and could discourage legitimate fallback-tool calls.
    parts.append(build_tool_availability_table(
        phase, allowed_tools,
        show_phase_allows_line=(tool_filter is None),
    ))

    # Add mode decision matrix for exploitation only (not needed in post-expl, mode already determined)
    if phase == "exploitation" and attack_path_type == "cve_exploit":
        # Mode context
        target_types = "Dropper/Staged/Meterpreter" if is_statefull else "Command/In-Memory/Exec"
        post_expl_note = "Interactive session commands available" if is_statefull else "Re-run exploit with different CMD values"

        parts.append(MODE_DECISION_MATRIX.format(
            mode=post_expl_type,
            target_types=target_types,
            post_expl_note=post_expl_note
        ))

    # Pre-configured payload settings (LHOST/LPORT/tunnel: ngrok or chisel) — injected BEFORE attack
    # chain so the agent knows the payload direction regardless of attack path type.
    #
    # Injection conditions:
    #   1. exploitation phase + statefull mode (CVE exploit, brute force)
    #   2. phishing attack path in ANY phase — payloads are generated before
    #      exploitation (agent runs msfvenom during informational phase,
    #      and the "exploitation" in phishing IS when the target opens the file)
    needs_session_config = (
        (phase == "exploitation" and is_statefull)
        or attack_path_type == "phishing_social_engineering"
    )
    if needs_session_config:
        session_config = get_session_config_prompt()
        if session_config:
            parts.append(session_config)

    # Helper: resolve user skill content (used across all phases)
    def _resolve_user_skill() -> str | None:
        if not attack_path_type.startswith("user_skill:"):
            return None
        from project_settings import get_enabled_user_skills
        skill_id = attack_path_type.split(":", 1)[1]
        skill = next((s for s in get_enabled_user_skills() if s['id'] == skill_id), None)
        return f"## User Attack Skill: {skill['name']}\n\n{skill['content']}" if skill else None

    # Helper: inject built-in skill workflow prompts (used in both informational and exploitation).
    # Delegates to the module-level build_builtin_skill_workflow so LATS expand shares the same playbook.
    def _inject_builtin_skill_workflow() -> bool:
        _wf = build_builtin_skill_workflow(
            attack_path_type, allowed_tools, is_statefull, execution_trace)
        parts.extend(_wf)
        return bool(_wf)

    # Tool descriptions: render in EVERY phase for every allowed tool.
    # Phase toggle = enable/disable per phase, NOT field selection. If a
    # tool is in allowed_tools for the current phase, the LLM sees all
    # four fields (purpose, when_to_use, args_format, description) — same
    # contract across the three phases.
    parts.append(build_informational_tool_descriptions(allowed_tools))

    # Skill workflows are now ADDITIVE on top of the descriptions, not
    # replacements. The descriptions teach the LLM what each tool does;
    # the skill workflow tells it the playbook for the current attack.
    if phase == "informational":
        user_skill_content = _resolve_user_skill()
        if user_skill_content:
            parts.append(
                user_skill_content + "\n\n"
                "**Current phase is informational.** Follow the skill's reconnaissance "
                "steps to gather target info, then request transition to exploitation."
            )
        else:
            _inject_builtin_skill_workflow()

    elif phase == "exploitation":
        # Built-in skill workflows have curated tool playbooks for known
        # attack paths (CVE exploit, brute force, etc.). They append to
        # — not replace — the generic tool descriptions above.
        if not _inject_builtin_skill_workflow():
            if attack_path_type.startswith("user_skill:"):
                user_skill_content = _resolve_user_skill()
                if user_skill_content:
                    parts.append(user_skill_content)
                else:
                    parts.append(UNCLASSIFIED_EXPLOIT_TOOLS)
            elif attack_path_type.endswith("-unclassified"):
                parts.append(UNCLASSIFIED_EXPLOIT_TOOLS)
            # else: descriptions above are sufficient

        if not activate_post_expl:
            parts.append("\n**NOTE:** Post-exploitation phase is DISABLED. Complete exploitation and use action='complete'.\n")

    elif phase == "post_exploitation":
        user_skill_content = _resolve_user_skill()
        if user_skill_content:
            parts.append(
                user_skill_content + "\n\n"
                "**Current phase is post-exploitation.** Follow the skill's "
                "post-exploitation steps if defined, or use available tools."
            )
        elif "metasploit_console" in allowed_tools:
            if is_statefull:
                parts.append(POST_EXPLOITATION_TOOLS_STATEFULL)
            else:
                parts.append(POST_EXPLOITATION_TOOLS_STATELESS)
        # else: descriptions above are sufficient

    return "\n".join(parts)


# Export list for explicit imports
__all__ = [
    # Tool registry and builders
    "TOOL_REGISTRY",
    "build_tool_availability_table",
    "build_informational_tool_descriptions",
    "build_compact_tool_list",
    "build_informational_guidance",
    "build_attack_path_behavior",
    "build_tool_args_section",
    "build_tool_name_enum",
    "build_phase_definitions",
    # Base prompts
    "MODE_DECISION_MATRIX",
    "REACT_SYSTEM_PROMPT",
    "PENDING_OUTPUT_ANALYSIS_SECTION",
    "PENDING_PLAN_OUTPUTS_SECTION",
    "RESPONSE_CLASS_TAXONOMY_BLOCK",
    "PHASE_TRANSITION_MESSAGE",
    "USER_QUESTION_MESSAGE",
    "FINAL_REPORT_PROMPT",
    "CONVERSATIONAL_RESPONSE_PROMPT",
    "SUMMARY_RESPONSE_PROMPT",
    "determine_response_tier",
    "TEXT_TO_CYPHER_SYSTEM",
    # Classification
    "ATTACK_PATH_CLASSIFICATION_PROMPT",
    "build_classification_prompt",
    # CVE exploit
    "CVE_EXPLOIT_TOOLS",
    "CVE_PAYLOAD_GUIDANCE_STATEFULL",
    "CVE_PAYLOAD_GUIDANCE_STATELESS",
    "NO_MODULE_FALLBACK_STATEFULL",
    "NO_MODULE_FALLBACK_STATELESS",
    # Hydra brute force
    "HYDRA_BRUTE_FORCE_TOOLS",
    "HYDRA_WORDLIST_GUIDANCE",
    # Phishing / Social Engineering
    "PHISHING_SOCIAL_ENGINEERING_TOOLS",
    "PHISHING_PAYLOAD_FORMAT_GUIDANCE",
    # Denial of Service
    "DOS_TOOLS",
    "DOS_VECTOR_SELECTION",
    "DOS_VERIFICATION_GUIDE",
    # SQL Injection
    "SQLI_TOOLS",
    "SQLI_OOB_WORKFLOW",
    "SQLI_PAYLOAD_REFERENCE",
    # XSS
    "XSS_TOOLS",
    "XSS_BLIND_WORKFLOW",
    "XSS_PAYLOAD_REFERENCE",
    # SSRF
    "SSRF_TOOLS",
    "SSRF_OOB_WORKFLOW",
    "SSRF_GOPHER_CHAINS",
    "SSRF_DNS_REBINDING",
    "SSRF_PAYLOAD_REFERENCE",
    "SSRF_CLOUD_PROVIDER_BLOCKS",
    "SSRF_CLOUD_DISABLED_STUB",
    # RCE
    "RCE_TOOLS",
    "RCE_AGGRESSIVE_DISABLED",
    "RCE_AGGRESSIVE_ENABLED",
    "RCE_OOB_WORKFLOW",
    "RCE_DESERIALIZATION_WORKFLOW",
    "RCE_PAYLOAD_REFERENCE",
    # Path Traversal / LFI / RFI
    "PATH_TRAVERSAL_TOOLS",
    "PATH_TRAVERSAL_PHP_WRAPPERS",
    "PATH_TRAVERSAL_OOB_WORKFLOW",
    "PATH_TRAVERSAL_ARCHIVE_EXTRACTION",
    "PATH_TRAVERSAL_PAYLOAD_REFERENCE",
    # Unclassified attack path
    "UNCLASSIFIED_EXPLOIT_TOOLS",
    "ACCESS_CONTROL_TOOLS",
    "HTTP_SMUGGLING_TOOLS",
    # XML External Entity (XXE) injection
    "XXE_TOOLS",
    "CRYPTO_ATTACK_TOOLS",
    # Post-exploitation
    "POST_EXPLOITATION_TOOLS_STATEFULL",
    "POST_EXPLOITATION_TOOLS_STATELESS",
    # Stealth rules
    "STEALTH_MODE_RULES",
    # Deep Think
    "DEEP_THINK_PROMPT",
    "DEEP_THINK_SECTION",
    "DEEP_THINK_SELF_REQUEST_INSTRUCTION",
    # Function
    "get_phase_tools",
]

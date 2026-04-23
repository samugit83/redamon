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

# Re-export from unclassified attack path prompts
from .unclassified_prompts import UNCLASSIFIED_EXPLOIT_TOOLS

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


def get_phase_tools(
    phase: str,
    activate_post_expl: bool = True,
    post_expl_type: str = "stateless",
    attack_path_type: str = "",
    execution_trace: list = None,
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
    allowed_tools = get_allowed_tools_for_phase(phase)

    # Kali shell library installation rules (prompt-based control)
    if "kali_shell" in allowed_tools:
        parts.append(build_kali_install_prompt())

    # Dynamic tool availability table — skip in informational phase where
    # build_informational_tool_descriptions() already provides full details
    if phase != "informational":
        parts.append(build_tool_availability_table(phase, allowed_tools))

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

    # Helper: inject built-in skill workflow prompts (used in both informational and exploitation)
    def _inject_builtin_skill_workflow() -> bool:
        """Inject skill-specific workflow if attack_path_type matches an enabled built-in skill.
        Returns True if a workflow was injected, False otherwise."""
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
            return True
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
            return True
        elif (attack_path_type == "denial_of_service"
                and "denial_of_service" in enabled_builtins
                and not (get_setting('ROE_ENABLED', False) and not get_setting('ROE_ALLOW_DOS', False))):
            dos_settings = get_dos_settings_dict()
            assessment_only = get_setting('DOS_ASSESSMENT_ONLY', False)
            dos_assessment_block = (
                "\n## ASSESSMENT ONLY MODE (ACTIVE)\n"
                "You are in ASSESSMENT-ONLY mode. Do NOT execute any DoS attack.\n"
                "Only research and report whether the target is VULNERABLE to DoS:\n"
                "- Run nmap scripts (--script dos, --script rdp-ms12-020)\n"
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
            return True
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
            return True
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
            return True
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
            return True
        return False

    # Add phase and ATTACK PATH specific workflow guidance
    if phase == "informational":
        # Dynamic tool descriptions (only shows allowed tools)
        parts.append(build_informational_tool_descriptions(allowed_tools))

        # Inject skill workflow — built-in skills get their full prompt from the start,
        # just like user skills. The workflow itself contains recon steps (Step 1: Target Analysis etc.)
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
        # SELECT WORKFLOW BASED ON ATTACK SKILL TYPE
        if not _inject_builtin_skill_workflow():
            # No built-in skill matched — check user skills and unclassified
            if attack_path_type.startswith("user_skill:"):
                user_skill_content = _resolve_user_skill()
                if user_skill_content:
                    parts.append(user_skill_content)
                else:
                    parts.append(UNCLASSIFIED_EXPLOIT_TOOLS)
            elif attack_path_type.endswith("-unclassified"):
                parts.append(UNCLASSIFIED_EXPLOIT_TOOLS)
            else:
                parts.append(build_informational_tool_descriptions(allowed_tools))

        # Add note about post-exploitation availability
        if not activate_post_expl:
            parts.append("\n**NOTE:** Post-exploitation phase is DISABLED. Complete exploitation and use action='complete'.\n")

    elif phase == "post_exploitation":
        # User skills define their own post-exploitation workflow
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
        else:
            # metasploit_console disabled — show only informational tool descriptions
            parts.append(build_informational_tool_descriptions(allowed_tools))

    return "\n".join(parts)


# Export list for explicit imports
__all__ = [
    # Tool registry and builders
    "TOOL_REGISTRY",
    "build_tool_availability_table",
    "build_informational_tool_descriptions",
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
    # Unclassified attack path
    "UNCLASSIFIED_EXPLOIT_TOOLS",
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

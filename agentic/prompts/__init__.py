"""
RedAmon Agent Prompts Package

System prompts for the ReAct agent orchestrator.
Includes phase-aware reasoning, tool descriptions, and structured output formats.
"""

# Re-export from base
from .base import (
    TOOL_AVAILABILITY,
    MODE_DECISION_MATRIX,
    INFORMATIONAL_TOOLS,
    METASPLOIT_CONSOLE_HEADER,
    REACT_SYSTEM_PROMPT,
    OUTPUT_ANALYSIS_PROMPT,
    PENDING_OUTPUT_ANALYSIS_SECTION,
    PHASE_TRANSITION_MESSAGE,
    USER_QUESTION_MESSAGE,
    FINAL_REPORT_PROMPT,
    TOOL_SELECTION_SYSTEM,
    TOOL_SELECTION_PROMPT,
    TEXT_TO_CYPHER_SYSTEM,
    TEXT_TO_CYPHER_PROMPT,
    FINAL_ANSWER_SYSTEM,
    FINAL_ANSWER_PROMPT,
)

# Re-export from classification
from .classification import ATTACK_PATH_CLASSIFICATION_PROMPT

# Re-export from CVE exploit prompts
from .cve_exploit_prompts import (
    CVE_EXPLOIT_TOOLS,
    CVE_PAYLOAD_GUIDANCE_STATEFULL,
    CVE_PAYLOAD_GUIDANCE_STATELESS,
)

# Re-export from brute force credential guess prompts
from .brute_force_credential_guess_prompts import (
    BRUTE_FORCE_CREDENTIAL_GUESS_TOOLS,
    BRUTE_FORCE_CREDENTIAL_GUESS_WORDLIST_GUIDANCE,
)

# Re-export from post-exploitation prompts
from .post_exploitation import (
    POST_EXPLOITATION_TOOLS_STATEFULL,
    POST_EXPLOITATION_TOOLS_SHELL,
    POST_EXPLOITATION_TOOLS_STATELESS,
)

# Backward compatibility aliases
EXPLOITATION_TOOLS = CVE_EXPLOIT_TOOLS
PAYLOAD_GUIDANCE_STATEFULL = CVE_PAYLOAD_GUIDANCE_STATEFULL
PAYLOAD_GUIDANCE_STATELESS = CVE_PAYLOAD_GUIDANCE_STATELESS

# Import utilities
from utils import get_session_config_prompt
from project_settings import get_setting


def get_phase_tools(
    phase: str,
    activate_post_expl: bool = True,
    post_expl_type: str = "stateless",
    attack_path_type: str = "cve_exploit"
) -> str:
    """Get tool descriptions for the current phase with attack path-specific guidance.

    Args:
        phase: Current agent phase (informational, exploitation, post_exploitation)
        activate_post_expl: If True, post-exploitation phase is available.
                           If False, exploitation is the final phase.
        post_expl_type: "statefull" for Meterpreter sessions, "stateless" for single commands.
        attack_path_type: Type of attack path ("cve_exploit", "brute_force_credential_guess")

    Returns:
        Concatenated tool descriptions appropriate for the phase, mode, and attack path.
    """
    parts = []
    is_statefull = post_expl_type == "statefull"

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

    # Determine allowed tools for current phase
    if phase == "informational":
        allowed_tools = "query_graph, web_search, execute_curl, execute_naabu"
    elif phase == "exploitation":
        allowed_tools = "query_graph, web_search, execute_curl, execute_naabu, metasploit_console"
    elif phase == "post_exploitation":
        allowed_tools = "query_graph, web_search, execute_curl, execute_naabu, metasploit_console"
    else:
        allowed_tools = "query_graph, web_search, execute_curl, execute_naabu"

    # Add tool availability matrix (concise, no redundancy)
    parts.append(TOOL_AVAILABILITY.format(phase=phase, allowed_tools=allowed_tools))

    # Add mode decision matrix for exploitation/post-expl (only for CVE exploit path)
    if phase in ["exploitation", "post_exploitation"] and attack_path_type == "cve_exploit":
        # Mode context
        target_types = "Dropper/Staged/Meterpreter" if is_statefull else "Command/In-Memory/Exec"
        post_expl_note = "Interactive session commands available" if is_statefull else "Re-run exploit with different CMD values"

        parts.append(MODE_DECISION_MATRIX.format(
            mode=post_expl_type,
            target_types=target_types,
            post_expl_note=post_expl_note
        ))

    # Add phase and ATTACK PATH specific workflow guidance
    if phase == "informational":
        parts.append(INFORMATIONAL_TOOLS)  # Full tool descriptions with examples

    elif phase == "exploitation":
        # SELECT WORKFLOW BASED ON ATTACK PATH TYPE
        if attack_path_type == "brute_force_credential_guess":
            # Format with max attempts from params
            parts.append(BRUTE_FORCE_CREDENTIAL_GUESS_TOOLS.format(
                brute_force_max_attempts=get_setting('BRUTE_FORCE_MAX_WORDLIST_ATTEMPTS', 3),
                bruteforce_speed=get_setting('BRUTEFORCE_SPEED', 5)
            ))
            # Add wordlist reference guide
            parts.append(BRUTE_FORCE_CREDENTIAL_GUESS_WORDLIST_GUIDANCE)
        else:
            # CVE-based exploitation (default)
            parts.append(CVE_EXPLOIT_TOOLS)
            # Select payload guidance based on post_expl_type
            payload_guidance = CVE_PAYLOAD_GUIDANCE_STATEFULL if is_statefull else CVE_PAYLOAD_GUIDANCE_STATELESS
            parts.append(payload_guidance)
            # Add pre-configured session settings for statefull mode only
            if is_statefull:
                session_config = get_session_config_prompt()
                if session_config:
                    parts.append(session_config)

        # Add note about post-exploitation availability
        if not activate_post_expl:
            parts.append("\n**NOTE:** Post-exploitation phase is DISABLED. Complete exploitation and use action='complete'.\n")

    elif phase == "post_exploitation":
        # Select post-exploitation tools based on mode AND attack path
        if is_statefull:
            if attack_path_type == "brute_force_credential_guess":
                # Shell session from SSH brute force
                parts.append(POST_EXPLOITATION_TOOLS_SHELL)
            else:
                # Meterpreter session from CVE exploit
                parts.append(POST_EXPLOITATION_TOOLS_STATEFULL)
        else:
            parts.append(POST_EXPLOITATION_TOOLS_STATELESS)

    return "\n".join(parts)


# Export list for explicit imports
__all__ = [
    # Base prompts
    "TOOL_AVAILABILITY",
    "MODE_DECISION_MATRIX",
    "INFORMATIONAL_TOOLS",
    "METASPLOIT_CONSOLE_HEADER",
    "REACT_SYSTEM_PROMPT",
    "OUTPUT_ANALYSIS_PROMPT",
    "PENDING_OUTPUT_ANALYSIS_SECTION",
    "PHASE_TRANSITION_MESSAGE",
    "USER_QUESTION_MESSAGE",
    "FINAL_REPORT_PROMPT",
    "TOOL_SELECTION_SYSTEM",
    "TOOL_SELECTION_PROMPT",
    "TEXT_TO_CYPHER_SYSTEM",
    "TEXT_TO_CYPHER_PROMPT",
    "FINAL_ANSWER_SYSTEM",
    "FINAL_ANSWER_PROMPT",
    # Classification
    "ATTACK_PATH_CLASSIFICATION_PROMPT",
    # CVE exploit
    "CVE_EXPLOIT_TOOLS",
    "CVE_PAYLOAD_GUIDANCE_STATEFULL",
    "CVE_PAYLOAD_GUIDANCE_STATELESS",
    # Brute force credential guess
    "BRUTE_FORCE_CREDENTIAL_GUESS_TOOLS",
    "BRUTE_FORCE_CREDENTIAL_GUESS_WORDLIST_GUIDANCE",
    # Post-exploitation
    "POST_EXPLOITATION_TOOLS_STATEFULL",
    "POST_EXPLOITATION_TOOLS_SHELL",
    "POST_EXPLOITATION_TOOLS_STATELESS",
    # Backward compatibility
    "EXPLOITATION_TOOLS",
    "PAYLOAD_GUIDANCE_STATEFULL",
    "PAYLOAD_GUIDANCE_STATELESS",
    # Function
    "get_phase_tools",
]

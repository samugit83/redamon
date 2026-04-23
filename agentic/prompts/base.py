"""
RedAmon Agent Base Prompts

Common prompts used across all attack paths.
"""

from .tool_registry import TOOL_REGISTRY


# =============================================================================
# TOOL REGISTRY — imported from tool_registry.py (single source of truth)
# =============================================================================

# =============================================================================
# DYNAMIC PROMPT BUILDERS
# =============================================================================

def _get_visible_tools(allowed_tools):
    """Get TOOL_REGISTRY entries for allowed tools, preserving registry order."""
    return [
        (name, info) for name, info in TOOL_REGISTRY.items()
        if name in allowed_tools
    ]


def build_tool_availability_table(phase, allowed_tools):
    """Build the tool availability table showing only tools allowed in the current phase."""
    visible = _get_visible_tools(allowed_tools)

    if not visible:
        return f"\n## Available Tools (Current Phase: {phase})\n\nNo tools available in this phase.\n"

    lines = [
        f"\n## Available Tools (Current Phase: {phase})\n",
        "| Tool                | Purpose                      | When to Use                                    |",
        "|---------------------|------------------------------|------------------------------------------------|",
    ]
    for name, info in visible:
        lines.append(f"| **{name}** | {info['purpose']} | {info['when_to_use']} |")

    lines.append(f"\n**Current phase allows:** {', '.join(t[0] for t in visible)}")
    return "\n".join(lines) + "\n"


def build_informational_tool_descriptions(allowed_tools):
    """Build detailed tool descriptions for only the allowed tools."""
    visible = [
        (name, info) for name, info in _get_visible_tools(allowed_tools)
        if info.get("description")
    ]

    if not visible:
        return ""

    parts = ["### Phase Tools\n"]
    for i, (name, info) in enumerate(visible, 1):
        parts.append(f"{i}. {info['description']}\n")

    return "\n".join(parts)


def build_tool_args_section(allowed_tools):
    """Build the tool arguments reference for allowed tools only."""
    visible = _get_visible_tools(allowed_tools)
    if not visible:
        return ""

    lines = ["### Tool Arguments:"]
    for name, info in visible:
        lines.append(f"- {name}: {{{{{info['args_format']}}}}}")
    return "\n".join(lines)


_FIRETEAM_PROMPT_BLOCK = """deploy_fireteam (2 to {max_members} specialists, fork-join on INDEPENDENT subtasks).

Fireteam = parallel REASONING (each specialist runs its own ReAct loop), not just parallel tool calls (that's plan_tools). Works in all phases.

Use when ALL hold:
1. Task splits into ≥2 subtasks; each needs ≥3 tool calls to do well.
2. Independent: no shared session/credential/meterpreter context/tmp file/singleton tool.
3. Sequential execution would take noticeable wall-clock.
4. No prior wave covered the same scope (check `(from <specialist>)` tags on findings in chain context).

Don't use when:
- One target/endpoint/session, subtasks share state, ≤2 tool calls total, or a subtask would itself need to fan out (members can't sub-fork).
- A previous wave already ran this plan → emit action=complete instead.

Escalation (cheapest first): use_tool → plan_tools → deploy_fireteam.
- plan_tools: you already know which N tools to call; ONE LLM call analyzes all outputs together. Cheap, shared context. Use when work = "fire these N commands and I'll interpret the combined result."
  EXAMPLES: `execute_nmap -sV 10.0.0.5` + `execute_httpx https://target` + `execute_subfinder -d target.com` in parallel (you read all three outputs yourself). Or `execute_curl /api/users` + `execute_curl /api/orders` + `execute_curl /api/admin` to check status codes on known endpoints.
- deploy_fireteam: N sub-agents reason independently, each picking their own tools across multiple iterations based on what they find. Expensive, deeper. Use when each subtask needs its OWN think-act-observe cycle.
  EXAMPLES: "map auth surface" (specialist renders page → inspects cookies → probes /api/auth endpoints → reports) + "map API surface" (specialist fuzzes /api → enumerates params on discoveries → probes nested paths) — each needs 3+ iterations and chooses its next tool from the last output.

Phase patterns:
- Informational: different surfaces of one target (auth / API / JS), or same technique across N targets. Skip if each surface fits in ≤2 tools.
- Exploitation: independent vuln classes on a mapped surface (SQLi / SSRF / auth-bypass). NOT a single multi-step exploit chain (sequential), NOT two members with `metasploit` skill (msfconsole singleton race — validator rejects).
- Post-exploitation: parallel research/planning tracks only. Multi-session msfconsole interaction is serialized through the singleton — do it yourself.

Hard limits: max {max_members} members per wave, dangerous tools escalate to operator, do NOT specify iteration counts.

After a wave returns: findings show `(from <specialist>)` and matching TODOs auto-complete. DO NOT redeploy the same plan. Either emit action=complete with a consolidated report, OR deploy a DIFFERENT plan if findings reveal a genuinely new surface. If user asked "deploy a fireteam to do X" and it did, the task is done.

Example (exploitation fan-out against a mapped surface):
```json
{{"action": "deploy_fireteam", "fireteam_plan": {{"members": [
  {{"name": "SQLi Operator", "task": "Exploit SQLi on /api/users?id= via UNION/blind; extract users table.", "skills": ["sqlmap", "curl"]}},
  {{"name": "SSRF Operator", "task": "Exploit SSRF on /api/fetch?url= to cloud metadata and internal services.", "skills": ["curl", "nuclei"]}},
  {{"name": "Auth Bypass", "task": "Test /admin for JWT alg-confusion, missing sig checks, and IDOR.", "skills": ["curl"]}}
], "plan_rationale": "Three independent vuln classes, no cross-dependency, no shared session"}}, ...}}
```

"""


_PROPENSITY_GUIDANCE = {
    1: (
        "## FIRETEAM PROPENSITY: 1/5 - VERY RELUCTANT\n"
        "Your operator has set you to the MOST CONSERVATIVE fireteam posture. "
        "You MUST NOT deploy a fireteam unless the task is EXTREMELY complex and has AT LEAST 3 clearly "
        "independent attack surfaces, EACH requiring 5 or more tool iterations on its own. "
        "In ALL other cases, prefer use_tool or plan_tools even if it means sequential work. "
        "When in doubt: DO NOT deploy.\n\n"
    ),
    2: (
        "## FIRETEAM PROPENSITY: 2/5 - RELUCTANT\n"
        "Your operator prefers single-agent or plan_tools execution. "
        "Deploy a fireteam ONLY when the task has AT LEAST 2 genuinely independent subtasks, each requiring "
        "4 or more tool iterations, AND sequential execution would waste significant wall-clock. "
        "For most tasks: use plan_tools instead.\n\n"
    ),
    4: (
        "## FIRETEAM PROPENSITY: 4/5 - EAGER\n"
        "Your operator favors parallel execution. When a task has ANY independent parallel angles "
        "(different attack surfaces, separate targets, distinct vuln classes), PREFER deploying a fireteam "
        "over sequential plan_tools. Even 2 subtasks with 2-3 tool iterations each is worth fanning out. "
        "Default to fireteam whenever the work is not strictly linear.\n\n"
    ),
    5: (
        "## FIRETEAM PROPENSITY: 5/5 - AGGRESSIVE\n"
        "Your operator has set you to MAXIMUM fan-out. You MUST deploy a fireteam for ANY task that "
        "can be split into 2 or more independent subtasks, regardless of how many tool iterations each needs. "
        "Parallel execution is the DEFAULT strategy. Only fall back to plan_tools or use_tool when the "
        "work is strictly sequential (shared session, single endpoint, dependent outputs). "
        "Err strongly on the side of deploying.\n\n"
    ),
}


def build_fireteam_prompt_fragments(enabled: bool, phase: str, allowed_phases, max_members: int = 5, propensity: int = 3):
    """Return (action_enum_fragment, plan_field_fragment, example_section).

    When enabled AND current phase is in allowed_phases, the fragments inject
    the deploy_fireteam action into the prompt. Otherwise they are empty
    strings, saving ~500 tokens per LLM call on sessions where Fireteam
    cannot run anyway. The think_node gate is still defensive — the LLM
    won't even see the action listed when gates are closed.

    ``max_members`` is threaded from project setting ``FIRETEAM_MAX_MEMBERS``
    (default 5) into the prompt text so the LLM sees the actual per-project cap
    rather than a hardcoded number. The Pydantic ``FireteamPlan`` model still
    enforces an absolute upper bound (8) at parse time as a safety net.

    ``propensity`` (1-5, default 3) tunes how eagerly the LLM is pushed
    toward deploy_fireteam vs cheaper alternatives. 3 emits no extra text
    (baseline). 1/2 prepend reluctant guidance; 4/5 prepend aggressive
    guidance. The text is strongly imperative so the LLM treats it as
    operator policy rather than advice.
    """
    gate_open = bool(enabled) and phase in (allowed_phases or [])
    if not gate_open:
        return ("", "", "")
    action_enum = "deploy_fireteam, "
    plan_field = '\n    "fireteam_plan": "<only if action=deploy_fireteam: see deploy_fireteam example below>",'
    # Use safe .format — no other curly-brace placeholders besides JSON literals
    # which are pre-escaped as {{ / }} in the template source.
    example = _PROPENSITY_GUIDANCE.get(int(propensity), "") + _FIRETEAM_PROMPT_BLOCK.format(max_members=int(max_members))
    return (action_enum, plan_field, example)


def build_tool_name_enum(allowed_tools):
    """Build the tool_name enum string for JSON examples."""
    visible = _get_visible_tools(allowed_tools)
    return ", ".join(name for name, _ in visible)


def build_phase_definitions():
    """Build Phase Definitions section — tool lists removed (Available Tools table covers them)."""
    lines = [
        "### Phase Definitions\n",
        "**INFORMATIONAL** (Default starting phase)",
        "- Purpose: Gather intelligence, understand the target, verify data",
        "- Neo4j contains existing reconnaissance data — primary source of truth\n",
        "**EXPLOITATION** (Requires user approval to enter)",
        "- Purpose: Actively exploit confirmed vulnerabilities",
        "- Prerequisites: Must have confirmed vulnerability AND user approval\n",
        "**POST-EXPLOITATION** (Requires user approval to enter)",
        "- Purpose: Actions on compromised systems",
        "- Prerequisites: Must have active session AND user approval",
        "\nSee **Available Tools** section below for tools allowed in the current phase.",
    ]

    return "\n".join(lines)



def build_attack_path_behavior(attack_path_type):
    """Build behavior rules for the ACTIVE attack path only.

    Previously showed rules for all 3 paths (~300 tokens), now only emits
    the active path's rules (~100-150 tokens).
    """
    if attack_path_type == "brute_force_credential_guess":
        return (
            "**SKIP username/credential reconnaissance** — brute force uses DEFAULT WORDLISTS with common usernames.\n"
            "In informational phase: Just verify the target service is reachable (1 query max), "
            "then IMMEDIATELY request transition to exploitation.\n"
            "Do NOT search the graph for usernames, credentials, or user accounts."
        )
    elif attack_path_type == "cve_exploit":
        return (
            "In informational phase: Gather target info (IP, port, service version, CVE details), "
            "then request transition to exploitation phase."
        )
    elif attack_path_type == "denial_of_service":
        return (
            "In informational phase: Gather target service info (version, OS), research known DoS "
            "vulnerabilities for the service, then request transition to exploitation.\n"
            "In exploitation: Follow the DoS workflow — execute attack, verify impact, "
            "then action='complete'. NEVER request post_exploitation — DoS does not provide access."
        )
    elif attack_path_type == "xss":
        return (
            "In informational phase: Use query_graph to surface existing Endpoints/Parameters/Forms, "
            "then render the target with execute_playwright to enumerate input vectors. "
            "Once vectors are mapped, request transition to exploitation.\n"
            "In exploitation: Follow the XSS workflow — canary sweep, kxss per-char filter probe, "
            "context-aware payloads, Playwright dialog-handler proof, dalfox WAF evasion if filtered, "
            "then action='complete' after PoC capture."
        )
    elif attack_path_type.startswith("user_skill:"):
        return (
            "Follow the attack skill workflow guidance provided in the Available Tools section.\n"
            "The skill defines phase-specific steps — follow them for the current phase."
        )
    elif attack_path_type.endswith("-unclassified"):
        return (
            "No mandatory workflow — use available tools based on the attack technique.\n"
            "In informational phase: Gather relevant target info, then request transition to exploitation.\n"
            "In exploitation: Use the generic exploitation workflow provided."
        )
    elif not attack_path_type:
        return ""  # Not yet classified
    else:
        return f"Follow the workflow guidance in the Available Tools section for attack path: {attack_path_type}"


def build_kali_install_prompt():
    """Build kali_shell library installation rules from project settings."""
    from project_settings import get_setting

    enabled = get_setting('KALI_INSTALL_ENABLED', False)
    if not enabled:
        return (
            "\n## Kali Shell — Library Installation: DISABLED\n\n"
            "**DO NOT install any packages** (pip install, apt install, apt-get install) via kali_shell.\n"
            "Only use pre-installed tools and libraries.\n"
        )

    parts = [
        "\n## Kali Shell — Library Installation: ALLOWED\n\n"
        "You MAY install packages via `pip install` or `apt install` in kali_shell "
        "when needed for a specific attack or activity. "
        "Installed packages are **ephemeral** — they are lost on container restart.\n"
    ]

    allowed = get_setting('KALI_INSTALL_ALLOWED_PACKAGES', '')
    forbidden = get_setting('KALI_INSTALL_FORBIDDEN_PACKAGES', '')

    if allowed.strip():
        parts.append(
            f"**Authorized packages (whitelist):** Only these may be installed: `{allowed.strip()}`\n"
            "Do NOT install any package not in this list.\n"
        )

    if forbidden.strip():
        parts.append(
            f"**Forbidden packages (blacklist):** NEVER install these: `{forbidden.strip()}`\n"
        )

    return "\n".join(parts)


def build_roe_prompt_section():
    """Build the Rules of Engagement prompt section from project settings.

    Returns a formatted string to inject into the system prompt when RoE is enabled.
    """
    from project_settings import get_setting

    if not get_setting('ROE_ENABLED', False):
        return ""

    sections = ["## RULES OF ENGAGEMENT (MANDATORY)"]

    # Client & engagement info
    client = get_setting('ROE_CLIENT_NAME', '')
    contact_name = get_setting('ROE_CLIENT_CONTACT_NAME', '')
    contact_email = get_setting('ROE_CLIENT_CONTACT_EMAIL', '')
    contact_phone = get_setting('ROE_CLIENT_CONTACT_PHONE', '')
    emergency = get_setting('ROE_EMERGENCY_CONTACT', '')
    start_date = get_setting('ROE_ENGAGEMENT_START_DATE', '')
    end_date = get_setting('ROE_ENGAGEMENT_END_DATE', '')
    eng_type = get_setting('ROE_ENGAGEMENT_TYPE', 'external')

    if client or contact_name:
        contact_parts = []
        if contact_name:
            contact_parts.append(contact_name)
        if contact_email:
            contact_parts.append(contact_email)
        if contact_phone:
            contact_parts.append(contact_phone)
        contact_str = f" | Contact: {', '.join(contact_parts)}" if contact_parts else ""
        sections.append(f"**Client:** {client}{contact_str}")

    if start_date or end_date:
        sections.append(f"**Engagement:** {start_date} to {end_date} | Type: {eng_type}")

    if emergency:
        sections.append(f"**Emergency Contact:** {emergency}")

    # Excluded hosts
    excluded = get_setting('ROE_EXCLUDED_HOSTS', [])
    excluded_reasons = get_setting('ROE_EXCLUDED_HOST_REASONS', [])
    if excluded:
        host_lines = []
        for i, host in enumerate(excluded):
            reason = excluded_reasons[i] if i < len(excluded_reasons) else ""
            reason_str = f" ({reason})" if reason else ""
            host_lines.append(f"  - {host}{reason_str}")
        sections.append("**EXCLUDED HOSTS (NEVER TOUCH):**\n" + "\n".join(host_lines))

    # Time window
    if get_setting('ROE_TIME_WINDOW_ENABLED', False):
        tz = get_setting('ROE_TIME_WINDOW_TIMEZONE', 'UTC')
        days = get_setting('ROE_TIME_WINDOW_DAYS', [])
        start_t = get_setting('ROE_TIME_WINDOW_START_TIME', '09:00')
        end_t = get_setting('ROE_TIME_WINDOW_END_TIME', '18:00')
        days_str = ", ".join(d.capitalize() for d in days) if days else "All days"
        sections.append(f"**Allowed Time Window:** {days_str} {start_t}-{end_t} {tz}")

    # Testing permissions
    perm_lines = []
    perm_flags = [
        ('ROE_ALLOW_DOS', 'DoS'),
        ('ROE_ALLOW_SOCIAL_ENGINEERING', 'Social Engineering'),
        ('ROE_ALLOW_PHYSICAL_ACCESS', 'Physical Access'),
        ('ROE_ALLOW_DATA_EXFILTRATION', 'Data Exfiltration'),
        ('ROE_ALLOW_ACCOUNT_LOCKOUT', 'Account Lockout'),
        ('ROE_ALLOW_PRODUCTION_TESTING', 'Production Testing'),
    ]
    for key, label in perm_flags:
        val = get_setting(key, False)
        perm_lines.append(f"  - {label}: {'ALLOWED' if val else 'PROHIBITED'}")
    sections.append("**Testing Permissions:**\n" + "\n".join(perm_lines))

    # Forbidden tools and categories
    forbidden_tools = get_setting('ROE_FORBIDDEN_TOOLS', [])
    forbidden_cats = get_setting('ROE_FORBIDDEN_CATEGORIES', [])
    if forbidden_tools:
        sections.append(f"**Forbidden Tools:** {', '.join(forbidden_tools)}")
    if forbidden_cats:
        sections.append(f"**Forbidden Categories:** {', '.join(forbidden_cats)}")

    # Severity cap
    max_phase = get_setting('ROE_MAX_SEVERITY_PHASE', 'post_exploitation')
    phase_labels = {
        'informational': 'Informational only (recon/scanning)',
        'exploitation': 'Up to exploitation',
        'post_exploitation': 'All phases (no restriction)',
    }
    sections.append(f"**Max Allowed Phase:** {phase_labels.get(max_phase, max_phase)}")

    # Rate limit
    rps = get_setting('ROE_GLOBAL_MAX_RPS', 0)
    if rps > 0:
        sections.append(f"**Global Rate Limit:** {rps} requests/sec")

    # Data handling
    data_handling = get_setting('ROE_SENSITIVE_DATA_HANDLING', 'no_access')
    data_labels = {
        'no_access': 'Do NOT access, copy, or display any sensitive data',
        'prove_access_only': 'Note existence of sensitive data but do NOT copy or display it',
        'limited_collection': 'Limited collection allowed — minimize data captured',
        'full_access': 'Full access — collect as needed for proof',
    }
    data_parts = [f"**Data Handling:** {data_labels.get(data_handling, data_handling)}"]
    retention_days = get_setting('ROE_DATA_RETENTION_DAYS', 90)
    if retention_days:
        data_parts.append(f"Data retention: {retention_days} days")
    if get_setting('ROE_REQUIRE_DATA_ENCRYPTION', True):
        data_parts.append("All test data must be encrypted at rest and in transit")
    sections.append(" | ".join(data_parts))

    # Compliance
    frameworks = get_setting('ROE_COMPLIANCE_FRAMEWORKS', [])
    if frameworks:
        sections.append(f"**Compliance:** {', '.join(frameworks)} — testing must respect these frameworks")

    # Third-party providers
    providers = get_setting('ROE_THIRD_PARTY_PROVIDERS', [])
    if providers:
        sections.append(f"**Third-Party Providers:** {', '.join(providers)}")

    # Communication
    update_freq = get_setting('ROE_STATUS_UPDATE_FREQUENCY', 'daily')
    critical_notify = get_setting('ROE_CRITICAL_FINDING_NOTIFY', True)
    sections.append(f"**Status Updates:** {update_freq} | Critical finding notify: {'YES' if critical_notify else 'NO'}")

    # Incident procedure
    incident = get_setting('ROE_INCIDENT_PROCEDURE', '')
    if incident:
        sections.append(f"**Incident Procedure:** {incident}")

    # Notes
    notes = get_setting('ROE_NOTES', '')
    if notes:
        sections.append(f"**Additional Rules:** {notes}")

    # Enforcement reminder
    sections.append(
        "\nYou MUST respect ALL rules above. Never target excluded hosts. "
        "Never use forbidden tools or techniques. Stay within the allowed phase. "
        "If you discover a critical vulnerability and critical finding notify is YES, flag it immediately."
    )

    # Raw text excerpt for additional context
    raw_text = get_setting('ROE_RAW_TEXT', '')
    if raw_text:
        truncated = raw_text[:3000]
        if len(raw_text) > 3000:
            truncated += "\n... (truncated)"
        sections.append(f"\n### Original RoE Document Excerpt\n```\n{truncated}\n```")

    return "\n\n".join(sections)


def build_informational_guidance(phase):
    """Build Intent Detection + Graph-First sections for informational phase only.

    These sections are irrelevant in exploitation/post-exploitation (intent is
    already determined, research workflow doesn't apply), saving ~380 tokens
    per exploitation iteration.
    """
    if phase != "informational":
        return ""

    return """## Intent Detection + Graph-First (informational phase)

Classify the user request by intent, then act:

- **Exploitation intent** ("exploit", "pwn", "run exploit", "use metasploit", "test vulnerability"): query the graph ONCE for target info (IP/port/service/CVE), then request `transition_phase` to exploitation. Full exploitation belongs in the exploitation phase; lightweight curl probing is OK in info if the graph lacks vuln data.
- **Payload/handler intent** ("generate", "payload", "reverse shell", "msfvenom", "handler", "listener", "one-liner", "backdoor"): request `transition_phase` to exploitation immediately. Do NOT generate payloads or start listeners from informational. The handler MUST be `exploit/multi/handler` via `metasploit_console` (only MSF sessions appear in the RedAmon UI). msfvenom generation via `kali_shell` is fine.
- **Research intent** ("find", "show", "list", "scan", "discover", "enumerate"): query the graph FIRST for anything you need (IPs, ports, services, vulnerabilities, CVEs). Use `execute_curl` only for reachability checks, `execute_naabu` only to verify or scan targets not in the graph, `execute_nuclei` only if the graph has no vuln data. Never re-test what the graph already shows.
"""


# =============================================================================
# MODE DECISION MATRIX
# =============================================================================

MODE_DECISION_MATRIX = """
## Current Mode: {mode}

| Mode       | Session Type        | TARGET Required              | Payload Type            | Post-Exploitation                |
|------------|---------------------|------------------------------|-------------------------|----------------------------------|
| Statefull  | Meterpreter/shell   | Dropper/Staged/Meterpreter   | Session-capable (bind/reverse) | Interactive commands, file ops   |
| Stateless  | None (output only)  | Command/In-Memory/Exec       | cmd/*/generic           | Re-run exploit with new CMD      |

**Your current configuration:** Mode={mode}
- **TARGET types to use:** {target_types}
- **Post-exploitation:** {post_expl_note}

**Important:** TARGET selection MUST match your mode. Wrong TARGET type means exploit may succeed but you get no session (statefull) or no output (stateless).
"""


# =============================================================================
# REACT SYSTEM PROMPT
# =============================================================================

REACT_SYSTEM_PROMPT = """You are RedAmon, an AI penetration testing assistant using the ReAct (Reasoning and Acting) framework.

## Your Operating Model

You work step-by-step using the Thought-Tool-Output pattern:
1. **Thought**: Analyze what you know and what you need to learn
2. **Action**: Select and execute the appropriate tool
3. **Observation**: Analyze the tool output
4. **Reflection**: Update your understanding and todo list

## Current Phase: {current_phase}

{phase_definitions}

## Orchestrator Auto-Logic

- Same-phase transitions are silently ignored — don't re-request your current phase
- Exploitation → Informational: auto-approved (safe downgrade)
- Info → Exploitation, Exploitation → Post-Expl: require user approval via action="transition_phase"
- Sessions auto-detected from output ("session X opened") and added to target_info — no manual tracking needed
- First `metasploit_console` call per session auto-resets msfconsole state
- Tool output is auto-truncated to prevent context overflow

{informational_guidance}

## Available Tools

{available_tools}

## Attack Skill: {attack_path_type}

{attack_path_behavior}

Create minimal TODOs — follow the attack skill workflow for step-by-step guidance.

## Current State

**Iteration**: {iteration}/{max_iterations}
**Current Objective**: {objective}

### Previous Objectives
{objective_history_summary}

### Prior Attack Chain History
{prior_chain_history}

### Attack Chain Progress
{chain_context}

### Current Todo List
{todo_list}

### Known Target Information
{target_info}

### Previous Questions & Answers
{qa_history}

## Your Task

Based on the context above, decide your next action. You MUST output valid JSON:

**IMPORTANT: Only include fields relevant to your chosen action. Omit unused fields!**

```json
{{
    "thought": "Your analysis of the current situation and what needs to be done next",
    "reasoning": "Why you chose this specific action over alternatives",
    "action": "<one of: use_tool, plan_tools, {fireteam_action_enum}transition_phase, complete, ask_user>",
    "tool_name": "<only if action=use_tool: {tool_name_enum}>",
    "tool_args": "<only if action=use_tool: {{'question': '...'}} or {{'args': '...'}} or {{'command': '...'}}",
    "tool_plan": "<only if action=plan_tools: see plan_tools example below>",{fireteam_plan_field}
    "phase_transition": "<only if action=transition_phase>",
    "user_question": "<only if action=ask_user>",
    "completion_reason": "<only if action=complete>",
    "updated_todo_list": [
        {{"id": "task-id", "description": "Task description", "status": "pending", "priority": "high"}}
    ]
}}
```

**Examples** (include thought, reasoning, updated_todo_list with every action):

use_tool: `{{"action": "use_tool", "tool_name": "query_graph", "tool_args": {{"question": "Show all critical vulnerabilities"}}, ...}}`

transition_phase:
```json
{{"action": "transition_phase", "phase_transition": {{"to_phase": "exploitation", "reason": "...", "planned_actions": ["..."], "risks": ["..."]}}, ...}}
```

ask_user:
```json
{{"action": "ask_user", "user_question": {{"question": "Which exploit?", "context": "...", "format": "single_choice", "options": ["A", "B"]}}, ...}}
```

plan_tools (run multiple INDEPENDENT tools as a wave — use when 2+ tools have NO dependencies):
```json
{{"action": "plan_tools", "tool_plan": {{"steps": [{{"tool_name": "execute_nmap", "tool_args": {{"target": "10.0.0.1", "args": "-sV"}}, "rationale": "Port discovery"}}, {{"tool_name": "query_graph", "tool_args": {{"question": "What is known about 10.0.0.1?"}}, "rationale": "Check existing intel"}}], "plan_rationale": "Independent tools, no dependency between them"}}, ...}}
```
Do NOT include tools that depend on another tool's output — plan those in the NEXT iteration after seeing results.

{fireteam_example_section}complete: `{{"action": "complete", "completion_reason": "Successfully exploited target", ...}}`

### When to Use action="complete" (CRITICAL):

Use `action="complete"` when the **CURRENT objective** is achieved, NOT the entire conversation. The user may provide new objectives — all context (execution_trace, target_info, objective_history) is preserved.

**Exploitation Completion Triggers:**
- PoC/RCE: After capturing command output as proof (e.g., `uid=0(root)`)
- Defacement: After successfully modifying the target file/page
- Session Mode: After establishing a Meterpreter/shell session (then transition to post_exploitation)

**After success, STOP.** Do NOT verify/re-check, troubleshoot, run extra recon, or perform post-exploitation unless the user explicitly requests it. If output shows success, trust it and complete.

{tool_args_section}

### Important Rules:
1. ALWAYS update the todo_list to track progress
2. Mark completed tasks as "completed"
3. Add new tasks when you discover them
4. Detect user INTENT - exploitation requests should be fast, research can be thorough
5. **Add exploitation steps as TODO items** and mark them in_progress/completed as you go

### When to Ask User (action="ask_user"):
Use ask_user ONLY when you need user input that cannot be determined from graph, tool output, target_info, or qa_history:
- Multiple exploit options, target selection, parameter clarification (e.g., LHOST), session selection, risk decisions
"""


# =============================================================================
# PENDING OUTPUT ANALYSIS SECTION (injected into REACT_SYSTEM_PROMPT when tool output is pending)
# =============================================================================

PENDING_OUTPUT_ANALYSIS_SECTION = """
## Previous Tool Output (MUST ANALYZE)

The following tool was just executed. You MUST include an `output_analysis` object in your JSON response.

**Tool**: {tool_name}
**Arguments**: {tool_args}
**Success**: {success}
**Output**:
```
{tool_output}
```

### Analysis Instructions

Include an `output_analysis` object in your JSON response:
```json
"output_analysis": {{
    "interpretation": "What this output tells us about the target",
    "extracted_info": {{
        "primary_target": "IP or hostname of the target (ALWAYS include, used for graph linking)",
        "ports": [],
        "services": [],
        "technologies": [],
        "vulnerabilities": [],
        "credentials": [],
        "sessions": []
    }},
    "actionable_findings": ["Finding that requires follow-up"],
    "recommended_next_steps": ["Suggested next action"],
    "exploit_succeeded": false,
    "exploit_details": null
}}
```

**exploit_succeeded = true** ONLY when output shows:
- A Metasploit session was opened ("session X opened", "Meterpreter session X")
- Brute force credentials were found ("[+] Success: 'user:pass'")
- Stateless exploit returned proof of compromise (file contents, RCE output like "uid=0(root)")

**exploit_succeeded = false** for: partial progress, failed attempts, information gathering, module configuration.

When `exploit_succeeded` is true, include `exploit_details`:
```json
"exploit_details": {{
    "attack_type": "cve_exploit or brute_force",
    "target_ip": "IP of compromised target",
    "target_port": 80,
    "cve_ids": ["CVE-XXXX-XXXXX"],
    "username": "compromised user or null",
    "password": "compromised pass or null",
    "session_id": 1,
    "evidence": "Brief proof the exploit worked"
}}
```

### Chain Findings

Include `chain_findings` when the output reveals notable intelligence: confirmed vulns, found credentials, discovered services, exploit modules, defense detection, or successful attack outcomes.
Always emit `service_identified` findings when new ports/services are discovered, and `configuration_found` when new technologies are identified.
Use goal/outcome types when an attack objective is achieved: exploit_success, access_gained, privilege_escalation, data_exfiltration, lateral_movement, persistence_established, denial_of_service_success, social_engineering_success, remote_code_execution, session_hijacked.

```json
"chain_findings": [
  {{
    "finding_type": "<vulnerability_confirmed|credential_found|exploit_success|access_gained|privilege_escalation|service_identified|exploit_module_found|defense_detected|configuration_found|information_disclosure|data_exfiltration|lateral_movement|persistence_established|denial_of_service_success|social_engineering_success|remote_code_execution|session_hijacked|custom>",
    "severity": "<critical|high|medium|low|info>",
    "title": "Short finding description",
    "evidence": "Raw evidence excerpt from output",
    "related_cves": ["CVE-XXXX-XXXXX"],
    "related_ips": ["1.2.3.4", "sub.example.com"],
    "confidence": 90
  }}
]
```

Only include fields in `extracted_info` that have new information. Exception: ALWAYS include `primary_target` — it is required for graph linking.
Analyze the output FIRST, then decide your next action as usual.
"""


# =============================================================================
# PENDING PLAN OUTPUTS SECTION (injected when a tool plan wave has completed)
# =============================================================================

PENDING_PLAN_OUTPUTS_SECTION = """
## Plan Wave Outputs (MUST ANALYZE ALL)

The following {n_tools} tools from your plan wave have completed. Analyze ALL outputs together and include an `output_analysis` in your JSON response.

{tool_outputs_section}

Your `output_analysis` should cover ALL tool outputs holistically. Use this EXACT schema:
```json
"output_analysis": {{
    "interpretation": "Combined analysis of all tool outputs",
    "extracted_info": {{
        "primary_target": "IP or hostname (ALWAYS include — required for graph linking)",
        "ports": [22, 8080],
        "services": ["ssh", "http"],
        "technologies": ["Apache/2.4.49"],
        "vulnerabilities": ["CVE-2021-41773"],
        "credentials": [],
        "sessions": []
    }},
    "actionable_findings": ["Finding that requires follow-up"],
    "recommended_next_steps": ["Suggested next action"],
    "exploit_succeeded": false,
    "exploit_details": null,
    "chain_findings": [
      {{
        "finding_type": "<vulnerability_confirmed|credential_found|exploit_success|access_gained|privilege_escalation|service_identified|exploit_module_found|defense_detected|configuration_found|information_disclosure|data_exfiltration|lateral_movement|persistence_established|denial_of_service_success|social_engineering_success|remote_code_execution|session_hijacked|custom>",
        "severity": "<critical|high|medium|low|info>",
        "title": "Short finding description",
        "evidence": "Raw evidence excerpt from output",
        "related_cves": ["CVE-XXXX-XXXXX"],
        "confidence": 90
      }}
    ]
}}
```

IMPORTANT: `extracted_info` field names must be EXACTLY: `primary_target`, `ports`, `services`, `technologies`, `vulnerabilities`, `credentials`, `sessions`. These are used for graph linking — wrong names will break connections.
Then decide your next action as usual.
"""


# =============================================================================
# PHASE TRANSITION PROMPT
# =============================================================================

PHASE_TRANSITION_MESSAGE = """## Phase Transition Request

I need your approval to proceed from **{from_phase}** to **{to_phase}**.

### Reason
{reason}

### Planned Actions
{planned_actions}

### Potential Risks
{risks}

---

Please respond with:
- **Approve** - Proceed with the transition
- **Modify** - Modify the plan (provide your changes)
- **Abort** - Cancel and stay in current phase
"""


# =============================================================================
# USER QUESTION PROMPT
# =============================================================================

USER_QUESTION_MESSAGE = """## Question for User

I need additional information to proceed effectively.

### Question
{question}

### Why I'm Asking
{context}

### Response Format
{format}

### Options
{options}

### Default Value
{default}

---

Please provide your answer to continue.
"""


# =============================================================================
# FINAL REPORT PROMPT
# =============================================================================

FINAL_REPORT_PROMPT = """Generate a summary report of the penetration test session.

## Original Objective
{objective}

## Execution Summary
- Total iterations: {iteration_count}
- Final phase: {final_phase}
- Completion reason: {completion_reason}

## Execution Trace
{execution_trace}

## Target Intelligence Gathered
{target_info}

## Todo List Final Status
{todo_list}

---

Generate a concise but comprehensive report including:
1. **Summary**: Brief overview of what was accomplished
2. **Key Findings**: Most important discoveries
3. **Discovered Credentials**: Any valid credentials found during brute force attacks (username:password pairs with target host)
4. **Sessions Established**: Any active sessions from successful exploitation (session ID, type, target)
5. **Vulnerabilities Found**: List with severity if known
6. **Recommendations**: Next steps or remediation advice
7. **Limitations**: What couldn't be tested or verified
"""


# =============================================================================
# CONVERSATIONAL RESPONSE PROMPT (tier: conversational)
# =============================================================================

CONVERSATIONAL_RESPONSE_PROMPT = """You completed an informational request. Respond directly and naturally.

## Original Request
{objective}

## Completion Reason
{completion_reason}

## Data Gathered
{execution_trace}

## Target Intelligence
{target_info}

---

Respond directly to the user's request in a clear, conversational tone.
- Present the relevant data/findings clearly
- Use markdown formatting (tables, lists) if the data warrants it
- Do NOT use a report structure with numbered sections
- Do NOT include "Recommendations", "Limitations", or "Summary" headers
- If the data answers the question fully, just present it
- Be concise — this is a direct answer, not a report
"""


# =============================================================================
# SUMMARY RESPONSE PROMPT (tier: summary)
# =============================================================================

SUMMARY_RESPONSE_PROMPT = """Generate a brief summary of the completed task.

## Original Objective
{objective}

## Completion Reason
{completion_reason}

## Attack Skill Type
{attack_path_type}

## Execution Summary
- Total iterations: {iteration_count}
- Final phase: {final_phase}

## Execution Trace
{execution_trace}

## Target Intelligence Gathered
{target_info}

---

Generate a brief, focused summary. Structure depends on the attack path:

**For phishing/social engineering:**
1. **Payload Details**: What was generated (type, format, filename, location)
2. **Handler Status**: Whether the handler is running, which port/payload
3. **Delivery**: How to deliver the artifact (file download, email, web delivery URL)

**For reconnaissance/scanning:**
1. **Summary**: What was discovered
2. **Key Findings**: Important results with details

**For other attack paths:**
1. **Summary**: Brief overview of what was accomplished
2. **Key Findings**: Most important discoveries
3. **Next Steps**: What could be done next (if relevant)

Keep it concise — 2-3 short sections maximum. No "Limitations" section unless something critical failed.
"""


# =============================================================================
# RESPONSE TIER DETERMINATION
# =============================================================================

def determine_response_tier(
    execution_trace: list,
    attack_path_type: str,
    target_info: dict,
    objective_history: list,
) -> str:
    """Determine the response tier based on state signals.

    Returns: "conversational", "summary", or "full_report"
    """
    # Count tool calls for the CURRENT objective only
    completed_step_ids: set = set()
    for outcome in (objective_history or []):
        completed_step_ids.update(outcome.get("execution_steps", []))

    current_steps = [
        s for s in execution_trace
        if s.get("step_id") not in completed_step_ids
    ]

    tool_calls = [s for s in current_steps if s.get("tool_name")]
    tool_count = len(tool_calls)

    # Unique tool names used (excluding query_graph which is passive)
    active_tools = {s["tool_name"] for s in tool_calls if s["tool_name"] != "query_graph"}
    only_graph_queries = len(active_tools) == 0 and tool_count > 0

    # Check which phases were reached during the current objective
    phases_reached = {s.get("phase") for s in current_steps if s.get("phase")}
    reached_exploitation = "exploitation" in phases_reached or "post_exploitation" in phases_reached

    # Check if credentials or sessions were found
    has_credentials = bool(target_info.get("credentials"))
    has_sessions = bool(target_info.get("sessions"))

    # --- Phishing/SE always gets summary (report sections don't apply) ---
    if attack_path_type in ("phishing_social_engineering", "denial_of_service"):
        return "summary"

    # --- Tier 1: Conversational ---
    if tool_count == 0:
        return "conversational"
    if only_graph_queries and not reached_exploitation:
        return "conversational"

    # --- Tier 3: Full Report ---
    if reached_exploitation and tool_count >= 5:
        return "full_report"
    if attack_path_type in ("cve_exploit", "brute_force_credential_guess"):
        if has_credentials or has_sessions:
            return "full_report"

    # --- Tier 2: Summary (everything else) ---
    return "summary"


TEXT_TO_CYPHER_SYSTEM = """You are a Neo4j Cypher query expert for a security reconnaissance database.

## Graph Database Overview
This is a multi-tenant security reconnaissance database storing OSINT and vulnerability data.
Each node has `user_id` and `project_id` properties for tenant isolation (handled automatically).

## Node Types and Key Properties

### Infrastructure Nodes (Hierarchy: Domain -> Subdomain -> IP -> Port -> Service)

**Domain** - Root domain being assessed
- name (string): "example.com"
- registrar, creation_date, expiration_date (WHOIS data)
- gvm_critical, gvm_high, gvm_medium, gvm_low (GVM vulnerability counts)
- vt_enriched (boolean), vt_reputation (int), vt_malicious_count (int), vt_categories (string): VirusTotal domain reputation
- vt_suspicious_count, vt_harmless_count, vt_undetected_count (int): VirusTotal engine detection breakdown
- vt_registrar (string): Registrar from VirusTotal
- vt_tags (list): VirusTotal threat/category tags (e.g. ["malware", "phishing"])
- vt_community_malicious, vt_community_harmless (int): VirusTotal community votes (distinct from engine count)
- vt_last_analysis_date (int): Unix timestamp of last VirusTotal scan
- vt_jarm (string): JARM TLS fingerprint from VirusTotal
- vt_popularity_alexa (int): Alexa popularity rank from VirusTotal
- vt_popularity_umbrella (int): Cisco Umbrella rank from VirusTotal
- otx_pulse_count (int): AlienVault OTX threat pulse count
- otx_url_count (int): number of URLs associated with domain from OTX url_list
- otx_adversaries (list[string]): named threat actors from OTX pulses (e.g. ["APT28", "Lazarus Group"])
- otx_malware_families (list[string]): malware family names from OTX pulses
- otx_tlp (string): most restrictive Traffic Light Protocol across OTX pulses ("white","green","amber","red")
- otx_attack_ids (list[string]): MITRE ATT&CK IDs from OTX pulses (e.g. ["T1566", "T1059"])
- criminalip_enriched (boolean): whether Criminal IP domain report was fetched
- criminalip_risk_score (string): domain risk score from Criminal IP
- criminalip_risk_grade (string): domain risk grade from Criminal IP
- criminalip_abuse_count (int): number of abuse reports for this domain from Criminal IP
- criminalip_current_service (string): current service classification from Criminal IP

**Subdomain** - Discovered subdomains
- name (string): "api.example.com", "www.example.com"
- has_dns_records (boolean): whether DNS records were resolved
- status (string): "resolved" (DNS only, not yet probed), "no_http" (no HTTP response), or HTTP status code as string ("200", "301", "403", "404", "500", etc.)
- status_codes (list[int]): all unique HTTP status codes seen e.g. [200, 301, 404]
- http_live_url_count (int): count of URLs with status < 500
- http_probed_at (datetime): when last HTTP-probed
- source (string): discovery source ("crt.sh", "hackertarget", "knockpy", "shodan_rdns", "shodan_dns", "urlscan", "fofa", "otx_passive_dns", "censys_rdns", "uncover")

**IP** - Resolved IP addresses
- address (string): "192.168.1.1"
- is_ipv6 (boolean)
- asn, isp, country (IP enrichment data)
- shodan_enriched, censys_enriched, fofa_enriched, netlas_enriched, zoomeye_enriched (boolean): which OSINT tools enriched this IP
- zoomeye_last_seen (string): ISO timestamp of the ZoomEye host record update_time (e.g. "2026-03-01T12:00:00")
- otx_enriched (boolean): whether OTX enrichment ran for this IP
- otx_pulse_count (int): AlienVault OTX threat pulse count
- otx_reputation (int): OTX reputation score (negative = more malicious)
- otx_url_count (int): number of URLs associated with this IP from OTX url_list
- otx_adversaries (list[string]): named threat actors from OTX pulses (e.g. ["APT28"])
- otx_malware_families (list[string]): malware family names from OTX pulses
- otx_tlp (string): most restrictive TLP across OTX pulses ("white","green","amber","red")
- otx_attack_ids (list[string]): MITRE ATT&CK IDs from OTX pulses (e.g. ["T1059"])
- country_name (string): country name from OTX geo (only set if not already populated by other enrichers)
- vt_enriched (boolean), vt_reputation (int), vt_malicious_count (int): VirusTotal multi-engine reputation
- vt_suspicious_count, vt_harmless_count, vt_undetected_count (int): VirusTotal engine detection breakdown
- vt_tags (list): VirusTotal threat tags (e.g. ["scanner", "vpn"])
- vt_community_malicious, vt_community_harmless (int): VirusTotal community votes
- vt_last_analysis_date (int): Unix timestamp of last VirusTotal scan
- vt_network (string): CIDR network range from VirusTotal (e.g. "44.224.0.0/11")
- vt_rir (string): Regional Internet Registry (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC)
- vt_continent (string): Continent code from VirusTotal
- vt_jarm (string): JARM TLS fingerprint from VirusTotal
- criminalip_enriched (boolean), criminalip_score_inbound, criminalip_score_outbound: Criminal IP risk scores (integer 0-5 or label string)
- criminalip_is_vpn, criminalip_is_proxy, criminalip_is_tor (boolean): Criminal IP anonymisation flags
- criminalip_is_hosting, criminalip_is_cloud (boolean): hosting/cloud infrastructure flags from Criminal IP
- criminalip_is_mobile, criminalip_is_darkweb, criminalip_is_scanner, criminalip_is_snort (boolean): Criminal IP threat classification flags
- criminalip_org_name (string): organization name from Criminal IP WHOIS
- criminalip_country (string): country code from Criminal IP WHOIS
- criminalip_city (string): city from Criminal IP WHOIS
- criminalip_latitude, criminalip_longitude (float): geolocation from Criminal IP WHOIS
- criminalip_asn_name (string): AS name from Criminal IP WHOIS
- criminalip_asn_no (int): AS number from Criminal IP WHOIS
- criminalip_ids_count (int): count of IDS/Snort alert records for this IP
- criminalip_scanning_count (int): count of inbound scanning events recorded by Criminal IP
- criminalip_categories (string): JSON list of IP threat category labels (e.g. '["malware", "scanner"]')
- autonomous_system_name, autonomous_system_number, asn_bgp_prefix, asn_description, asn_country_code, asn_rir: ASN details from Censys
- country_code, city, timezone, registered_country, latitude, longitude: geolocation from Censys or Netlas
- censys_last_seen (datetime): last scan time from Censys
- asn_org (string): ASN organization name from Netlas (whois.asn.name) or FOFA (as_organization)
- asn (string): ASN identifier e.g. "AS14618" from Netlas (geo.asn.number) or FOFA (as_number, normalised to "AS<n>")
- fofa_last_seen (string): last time FOFA indexed this asset (ISO datetime string)
- os (string): OS fingerprint from FOFA (os field)
- region (string): region/province from FOFA (region field)
- uncover_discovered (boolean): IP was first found via ProjectDiscovery uncover multi-engine search
- uncover_enriched (boolean): uncover has processed this IP
- uncover_sources (list[string]): search engines that returned results (e.g. shodan, censys, fofa)
- uncover_source_counts (string): JSON-encoded dict of engine->result count
- uncover_total_raw (integer): total raw results before deduplication
- uncover_total_deduped (integer): total results after deduplication

**Port** - Open ports on IPs
- number (integer): 80, 443, 22
- protocol (string): "tcp", "udp"
- state (string): "open", "closed", "filtered"
- source (string): which tool discovered it ("naabu", "masscan", "shodan", "censys", "fofa", "netlas", "zoomeye", "criminalip", "uncover")
- product (string): software product from Nmap -sV (e.g. "vsftpd", "Apache Tomcat", "MySQL")
- version (string): software version from Nmap -sV (e.g. "2.3.4", "8.5.19")
- cpe (string): CPE string from Nmap (e.g. "cpe:/a:vsftpd:vsftpd:2.3.4")
- nmap_scanned (boolean): true if Nmap has probed this port

**Service** - Services running on ports
- name (string): "http", "ssh", "mysql"
- product (string): software product from Nmap -sV or OSINT (e.g. "vsftpd", "OpenSSH", "nginx")
- version (string): service version
- cpe (string): CPE string from Nmap
- banner (string): raw banner
- source (string): which tool detected it
- extended_service_name (string): more specific label from Censys (e.g. "HTTPS")
- labels (list[string]): service classification tags from Censys
- http_title (string): HTML page title from HTTP response (Censys, Netlas, or FOFA title field)
- http_status_code (integer): HTTP status code (Censys or Netlas)
- software_products (list[string]): detected software and versions from Censys e.g. ["nginx 1.23"]
- banner (string): raw service banner (Censys, ZoomEye, Nmap, or Netlas protocol banner)
- app_protocol (string): application-layer protocol from FOFA (e.g. "http", "https", "ssh", "ftp")
- jarm (string): JARM TLS fingerprint from FOFA — useful for identifying C2 infrastructure
- tls_version (string): TLS version from FOFA (e.g. "TLSv1.3")

### Web Application Nodes (Hierarchy: BaseURL -> Endpoint -> Parameter)

**BaseURL** - HTTP-probed base URLs
- url (string): "https://api.example.com:443"
- status_code (integer): 200, 301, 404
- title (string): page title
- content_type (string): "text/html"
- final_url (string): after redirects

**Endpoint** - Discovered web endpoints/paths
- url (string): "https://api.example.com/api/v1/users"
- path (string): "/api/v1/users"
- method (string): "GET", "POST"
- status_code (integer)
- GraphQL enrichment (set by graphql_scan when endpoint is a GraphQL endpoint):
  - is_graphql (boolean): True if the endpoint is a GraphQL endpoint
  - graphql_introspection_enabled (boolean): True if __schema introspection query succeeded
  - graphql_schema_extracted (boolean): True if full schema was retrieved
  - graphql_schema_hash (string): SHA-256 of normalized schema JSON (change detection)
  - graphql_schema_extracted_at (datetime): ISO timestamp of schema extraction
  - graphql_queries (string[]): Up to 50 query operation names
  - graphql_mutations (string[]): Up to 50 mutation operation names
  - graphql_subscriptions (string[]): Up to 50 subscription operation names
  - graphql_queries_count, graphql_mutations_count, graphql_subscriptions_count (integer): Full counts
- graphql-cop capability flags (set by the external scanner, Phase 2):
  - graphql_cop_ran (boolean): True if graphql-cop executed against this endpoint
  - graphql_cop_scanned_at (datetime): ISO timestamp of last graphql-cop run
  - graphql_graphiql_exposed (boolean): GraphiQL / Playground UI detected
  - graphql_tracing_enabled (boolean): Apollo tracing extension is on
  - graphql_get_allowed (boolean): GET-method queries accepted (CSRF vector)
  - graphql_field_suggestions_enabled (boolean): "Did you mean X?" errors leak schema
  - graphql_batching_enabled (boolean): Array-based batched queries accepted

**Parameter** - URL/form parameters
- name (string): "id", "username", "page"
- type (string): "query", "body", "path"
- value (string): sample value if captured

### Technology & Security Nodes

**Technology** - Detected technologies (web servers, frameworks, CMS, services)
- name (string): "nginx", "WordPress", "jQuery", "vsftpd/2.3.4", "Apache Tomcat/8.5.19"
- version (string): version if detected
- category (string): "web-server", "cms", "javascript-framework"
- source (string): "nmap" for Nmap-detected, null for httpx-detected
- cpe (string): CPE string from Nmap (e.g. "cpe:/a:apache:tomcat:8.5.19")

**Header** - HTTP response headers
- name (string): "X-Frame-Options", "Content-Security-Policy"
- value (string): header value

**Certificate** - SSL/TLS certificates
- issuer, subject (string)
- not_before, not_after (datetime)
- is_expired (boolean)
- source (string): "gvm", "censys", or "fofa"
- subject_cn (string): certificate common name (Censys or FOFA certs_subject_cn)
- subject_org (string): certificate subject organization (FOFA certs_subject_org)
- tls_version (string): TLS version (FOFA tls_version)
- is_valid (boolean): certificate validity flag (FOFA certs_valid)
- issuer_cn (string): issuer common name (Censys)
- issuer_org (string): issuer organization (Censys)
- san (list[string]): Subject Alternative Names (Censys)
- fingerprint (string): certificate fingerprint (Censys)
- tls_version (string): TLS protocol version e.g. "TLSv1.3" (Censys)
- cipher (string): cipher suite (Censys)

**DNSRecord** - DNS records
- record_type (string): "A", "AAAA", "CNAME", "MX", "TXT", "NS"
- value (string): record value

**Secret** - Secrets discovered in live web resources (JS files, configs)
- secret_type (string): type of secret (AWSAccessKey, APIKey, GCPCredential, GitHubToken, etc.)
- severity (string): high, medium, low, info
- source (string): discovery tool (jsluice, etc.)
- source_url (string): URL of file containing the secret
- base_url (string): parent BaseURL
- sample (string): redacted sample of matched data

**Traceroute** - Network route from scanner to target (from GVM)
- target_ip (string): target IP address
- scanner_ip (string): scanner IP address
- hops (string[]): ordered list of hop IPs (scanner first, target last)
- distance (integer): number of network hops
- source (string): always "gvm"

### Vulnerability & CVE Nodes (CRITICAL: Two Different Node Types!)

**IMPORTANT: "Vulnerabilities" can mean BOTH Vulnerability nodes AND CVE nodes!**
- When user asks about "vulnerabilities" broadly, query BOTH node types
- Vulnerability nodes = findings from scanners (nuclei, gvm, security_check, netlas)
- CVE nodes = known CVEs linked to technologies detected on the target

**Vulnerability** - Scanner findings (from nuclei, gvm, security checks, netlas, graphql_scan)

Common properties (all sources):
- id (string): unique identifier
- name (string): vulnerability name
- severity (string): "critical", "high", "medium", "low", "info" (lowercase!)
- source (string): **"nuclei"** (DAST/web), **"gvm"** (network/OpenVAS), **"security_check"**, **"netlas"** (passive NVD-based), **"graphql_scan"** (GraphQL security testing), or **"takeover_scan"** (subdomain takeover via Subjack + Nuclei takeover templates)
- description (string): vulnerability description
- cvss_score (float): 0.0 to 10.0

Netlas-specific properties (source="netlas"):
- id (string): CVE identifier e.g. "CVE-2021-44228"
- has_exploit (boolean): whether a known public exploit exists (from NVD data)
- Relationship: `(svc:Service)-[:HAS_VULNERABILITY]->(v:Vulnerability)` — linked to the Service where the vulnerable software was detected

Nuclei-specific properties (source="nuclei"):
- template_id (string): nuclei template ID
- template_path, template_url (string): template location
- category (string): "xss", "sqli", "rce", "lfi", "ssrf", "exposure", etc.
- tags (list), authors (list), references (list)
- cwe_ids (list), cves (list), cvss_metrics (string)
- matched_at (string): URL where vuln was found
- matcher_name, matcher_status, extractor_name, extracted_results
- request_type, scheme, host, port, path, matched_ip
- is_dast_finding (boolean), fuzzing_method, fuzzing_parameter, fuzzing_position
- curl_command (string): reproduction command
- raw_request, raw_response (string): evidence

GVM-specific properties (source="gvm"):
- oid (string): OpenVAS NVT OID
- family (string): NVT family (e.g., "Web Servers")
- target_ip (string), target_port (integer), target_hostname (string), port_protocol (string)
- threat (string): "High", "Medium", "Low", "Log"
- solution (string), solution_type (string)
- qod (integer): Quality of Detection (0-100)
- qod_type (string): detection method type
- cve_ids (list): associated CVE IDs (stored as property, no CVE node relationships)
- cisa_kev (boolean): true if in CISA Known Exploited Vulnerabilities catalog
- remediated (boolean): true if marked as closed/patched by GVM re-scan
- scanner (string): always "OpenVAS"
- scan_timestamp (string): GVM scan timestamp

GraphQL-specific properties (source="graphql_scan"):
- vulnerability_type (string): one of "graphql_introspection_enabled", "graphql_sensitive_data_exposure"
- endpoint (string): the GraphQL endpoint URL (e.g. "https://api.target.com/graphql")
- title (string): human-readable finding title
- evidence (string): JSON blob with counts/fields (queries_count, mutations_count, subscriptions_count, sensitive_fields, schema_hash)
- timestamp (datetime): ISO timestamp of discovery
- id pattern: `graphql_{vulnerability_type}_{baseurl}_{path}` (deterministic, MERGE-safe across re-scans)
- Typical query: "find endpoints exposing GraphQL introspection" → `MATCH (e:Endpoint {is_graphql: true, graphql_introspection_enabled: true})-[:HAS_VULNERABILITY]->(v:Vulnerability) WHERE v.source IN ['graphql_scan', 'graphql_cop'] RETURN e.url, v.vulnerability_type, v.severity`

graphql-cop properties (source="graphql_cop" -- external Docker scanner, Phase 2):
- 12 distinct vulnerability_type values:
  - Info-leak: graphql_field_suggestions_enabled (LOW), graphql_ide_exposed (LOW), graphql_tracing_enabled (INFO), graphql_unhandled_error (INFO)
  - CSRF: graphql_get_method_allowed (MEDIUM), graphql_get_based_mutation (MEDIUM), graphql_post_csrf (MEDIUM)
  - DoS: graphql_alias_overloading (HIGH), graphql_batch_query_allowed (HIGH), graphql_directive_overloading (HIGH), graphql_circular_introspection (HIGH)
  - Overlap with native: graphql_introspection_enabled (when cop's introspection test is explicitly enabled)
- evidence (string): JSON blob with curl_verify (reproducer cURL), raw_severity (HIGH/MEDIUM/LOW/INFO), color, graphql_cop_key
- Same deterministic ID pattern — dedupes with graphql_scan when the same vulnerability_type fires on the same endpoint
- Typical query: "list all graphql-cop DoS findings" → `MATCH (v:Vulnerability {source: 'graphql_cop'}) WHERE v.vulnerability_type IN ['graphql_alias_overloading', 'graphql_batch_query_allowed', 'graphql_directive_overloading', 'graphql_circular_introspection'] RETURN v.vulnerability_type, v.severity, v.endpoint`

Subdomain-takeover properties (source="takeover_scan"):
- type (string): always "subdomain_takeover"
- hostname (string): the subdomain flagged (e.g. "promo.acme.com")
- cname_target (string, nullable): CNAME destination for cname-method findings (e.g. "acme-spring.herokuapp.com")
- takeover_provider (string): canonical provider slug — "github-pages", "heroku", "aws-s3", "fastly", "azure-app-service", "shopify", "ghost", "zendesk", "readthedocs", "netlify", "vercel", etc., or "unknown"
- takeover_method (string): "cname" | "dns" | "ns" | "mx" | "stale_a"
- confidence (integer): 0..100 score from the layered scanner
- sources (string[]): tools that confirmed the finding — subset of ["subjack", "nuclei_takeover"]
- confirmation_count (integer): length of sources
- verdict (string): "confirmed" (>=threshold+10), "likely" (>=threshold), or "manual_review" (below threshold). Manual-review findings are emitted with severity="info" unless the project opts into auto-publish.
- evidence (string): short human-readable excerpt of the match (subjack service name or nuclei template/matcher)
- tool_raw (string): JSON-encoded raw per-tool output (truncated to 50KB)
- first_seen / last_seen (strings): ISO timestamps
- id pattern: `takeover_<sha1-hex16>` where the hash is over `hostname+takeover_provider+takeover_method` — deterministic, MERGE-safe across re-scans
- Typical query: "list confirmed Heroku takeovers" → `MATCH (s:Subdomain)-[:HAS_VULNERABILITY]->(v:Vulnerability {source: 'takeover_scan'}) WHERE v.takeover_provider = 'heroku' AND v.verdict = 'confirmed' RETURN s.name AS subdomain, v.cname_target, v.confidence, v.sources`

**CVE** - Known CVE entries (linked to Technologies)
- id (string): "CVE-2021-41773", "CVE-2021-44228"
- name (string): same as id or descriptive name
- severity (string): "HIGH", "CRITICAL", "MEDIUM", "LOW" (uppercase from NVD!)
- cvss (float): CVSS score from NVD (0.0 to 10.0)
- description (string): CVE description
- source (string): "nvd" (from National Vulnerability Database)
- url (string): link to NVD page
- references (string): comma-separated reference URLs
- published (string): publication date

**MitreData** - MITRE ATT&CK/CWE entries
- id (string): "CWE-79", "T1190"
- name (string)
- type (string): "cwe" or "attack"

**Capec** - CAPEC attack patterns
- id (string): "CAPEC-86"
- name (string)

### Gvm Exploitation Nodes

**ExploitGvm** - GVM confirmed active exploitation (QoD=100, "Active Check")
- id (string): deterministic ID (gvm-exploit-{oid}-{ip}-{port})
- attack_type (string): always "cve_exploit"
- severity (string): always "critical" (confirmed compromise)
- target_ip (string), target_port (integer)
- cve_ids (string[]): CVE IDs exploited
- cisa_kev (boolean): CISA KEV flag
- evidence (string): full description with execution proof (e.g., uid=0(root))
- qod (integer): always 100
- source (string): always "gvm"
- oid (string): OpenVAS NVT OID

### Attack Chain Nodes (Agent Execution History)

**AttackChain** - Root of an attack chain (1:1 with a conversation session)
- chain_id (string): Unique, equals session ID
- title (string): conversation title / first message excerpt
- objective (string): attack objective text
- status (string): "active", "completed", or "aborted"
- attack_path_type (string): "cve_exploit" or "brute_force_credential_guess"
- total_steps (integer), successful_steps (integer), failed_steps (integer)
- phases_reached (string[]): phases visited e.g. ["informational", "exploitation"]
- final_outcome (string): completion summary
- created_at (datetime), updated_at (datetime)

**ChainStep** - Each tool execution in an attack chain
- step_id (string): Unique (UUID)
- chain_id (string): parent AttackChain
- iteration (integer): step number within chain
- phase (string): "informational", "exploitation", or "post_exploitation"
- tool_name (string): tool that was executed
- tool_args_summary (string): truncated tool arguments
- thought (string): agent's reasoning before action
- reasoning (string): agent's shorter reasoning excerpt
- output_summary (string): truncated tool output
- output_analysis (string): agent's interpretation of output
- success (boolean): whether the step succeeded
- error_message (string): error message if failed
- duration_ms (integer): step execution time
- created_at (datetime)

**ChainFinding** - Discovery during attack (replaces agent Exploit for exploit_success)
- finding_id (string): Unique (UUID)
- chain_id (string): parent AttackChain
- finding_type (string): vulnerability_confirmed, credential_found, exploit_success, access_gained, privilege_escalation, service_identified, exploit_module_found, defense_detected, configuration_found, information_disclosure, data_exfiltration, lateral_movement, persistence_established, denial_of_service_success, social_engineering_success, remote_code_execution, session_hijacked, custom
- severity (string): critical, high, medium, low, info
- title (string): short description
- description (string): detailed description
- evidence (string): raw evidence excerpt from output
- confidence (integer): 0-100
- phase (string): phase when found
- Exploit-specific (only when finding_type="exploit_success"):
  - attack_type (string), target_ip (string), target_port (integer)
  - cve_ids (string[]), metasploit_module (string), payload (string)
  - session_id (integer), username (string), password (string)
  - report (string), commands_used (string[])
- created_at (datetime)

**ChainDecision** - Strategic pivot point
- decision_id (string): Unique (UUID)
- chain_id (string): parent AttackChain
- decision_type (string): phase_transition, strategy_change, target_switch
- from_state (string), to_state (string), reason (string)
- made_by (string): "agent" or "user"
- approved (boolean)
- created_at (datetime)

**ChainFailure** - Failed attempt with lesson learned
- failure_id (string): Unique (UUID)
- chain_id (string): parent AttackChain
- failure_type (string): exploit_failed, authentication_failed, tool_error, timeout, connection_refused
- tool_name (string), error_message (string), lesson_learned (string)
- retry_possible (boolean), phase (string)
- created_at (datetime)

### TruffleHog Secret Scanner Nodes (Hierarchy: Domain -> TrufflehogScan -> TrufflehogRepository -> TrufflehogFinding)

**TrufflehogScan** - Scan metadata for a TruffleHog secret scan run
- target (string): scan target (e.g. GitHub org name)
- scan_start_time (string), scan_end_time (string): timestamps
- duration_seconds (float): scan duration
- status (string): "completed", "failed", "unknown"
- total_findings (integer), verified_findings (integer), unverified_findings (integer)
- repositories_scanned (integer)

**TrufflehogRepository** - A repository scanned by TruffleHog
- name (string): repository name (e.g. "org/repo-name")

**TrufflehogFinding** - A secret found by TruffleHog in a repository
- detector_name (string): detector type (e.g. "AWS", "GitHub", "PrivateKey", "Slack")
- detector_description (string): human-readable detector description
- verified (boolean): whether the secret was verified as active
- redacted (string): redacted secret value
- repository (string): repository name where found
- file (string): file path within the repository
- commit (string): git commit hash
- line (integer): line number in file
- link (string): URL to the finding location
- timestamp (string): commit timestamp
- extra_data (string): JSON string with additional detector-specific data

### JS Recon Scanner Nodes

**JsReconFinding** - JavaScript reconnaissance findings. Two sub-types:

1. **JS File nodes** (finding_type='js_file') - Represent each analyzed JavaScript file. All findings from that file are linked to this node.
   - finding_type: 'js_file'
   - title (string): filename (e.g. "app.js", "test_app.js")
   - detail (string): full URL or upload:// path
   - is_uploaded (boolean): true if manually uploaded, false if from pipeline crawl
   - source_url (string): full URL or upload://filename

2. **Finding nodes** (finding_type != 'js_file') - Individual findings linked to their parent JS file node.
   - finding_type (string): dependency_confusion, source_map_exposure, dom_sink, framework, dev_comment, source_map_reference
   - severity (string): critical, high, medium, low, info
   - confidence (string): high, medium, low
   - title (string): human-readable finding title
   - detail (string): full finding detail
   - evidence (string): matched pattern or code snippet
   - source_url (string): JS file where finding was discovered
   - source (string): always "js_recon"

Graph hierarchy: Domain/BaseURL -> JS file node -> findings/secrets/endpoints
- `(Domain)-[:HAS_JS_FILE]->(JsReconFinding {finding_type: 'js_file'})` for uploaded files
- `(BaseURL)-[:HAS_JS_FILE]->(JsReconFinding {finding_type: 'js_file'})` for pipeline-crawled files
- `(JsReconFinding {finding_type: 'js_file'})-[:HAS_JS_FINDING]->(JsReconFinding)` findings from that file
- `(JsReconFinding {finding_type: 'js_file'})-[:HAS_SECRET]->(Secret)` secrets found in that file
- `(JsReconFinding {finding_type: 'js_file'})-[:HAS_ENDPOINT]->(Endpoint)` endpoints extracted from that file

Note: JS Recon also creates Secret nodes with source='js_recon' and extra fields:
- validation_status (string): validated, invalid, unvalidated, skipped, incomplete
- validation_info (string): JSON with validation details (scope, account info)
- confidence (string): high, medium, low
- detection_method (string): regex
- key_type (string): category of secret (cloud, payment, auth, etc.)

When user asks about "JS findings", "JavaScript attack surface", "JS secrets", or "what did JS Recon find":
- First query JS file nodes: MATCH (jf:JsReconFinding {finding_type: 'js_file'})
- Then traverse to findings: (jf)-[:HAS_JS_FINDING]->(finding), (jf)-[:HAS_SECRET]->(s), (jf)-[:HAS_ENDPOINT]->(e)
- Query Secret nodes WHERE source = 'js_recon' for secrets
- Query Endpoint nodes WHERE source = 'js_recon' for JS-extracted endpoints

**ThreatPulse** - OTX threat intelligence pulses (named threat reports linking IPs/domains to adversaries)
- pulse_id (string): OTX pulse ID (UNIQUE per tenant)
- name (string): pulse title (e.g. "Lazarus Group C2 Infrastructure")
- adversary (string): named threat actor (e.g. "APT28", "Lazarus Group", "Sandworm")
- malware_families (list[string]): associated malware names (e.g. ["WannaCry", "BLINDINGCAN"])
- attack_ids (list[string]): MITRE ATT&CK technique IDs (e.g. ["T1566", "T1059"])
- tags (list[string]): free-form community tags (e.g. ["apt", "ransomware", "banking"])
- tlp (string): Traffic Light Protocol ("white","green","amber","red")
- author_name (string): pulse author
- targeted_countries (list[string]): countries targeted by this threat
- modified (string): last modified timestamp from OTX

**Malware** - Malware file samples (hashes) associated with IPs or domains (from OTX malware endpoint)
- hash (string): file hash — MD5 (32 chars) or SHA256 (64 chars); UNIQUE per tenant
- hash_type (string): "md5", "sha256", "sha1", "unknown"
- file_type (string): file class/type (e.g. "pe32", "pdf", "elf", "jar")
- file_name (string): original file name if available
- source (string): discovery tool ("otx", "virustotal")
- first_seen (datetime): when first associated with this indicator

**ExternalDomain** - Foreign domains encountered during recon (out-of-scope, informational only)
- domain (string): foreign domain name
- sources (string[]): discovery sources (http_probe_redirect, urlscan, gau, katana, hakrawler, jsluice, cert_discovery, otx_passive_dns)
- redirect_from_urls (string[]): in-scope URLs that redirected to this domain
- redirect_to_urls (string[]): foreign URLs encountered
- status_codes_seen (string[]), titles_seen (string[]), servers_seen (string[])
- ips_seen (string[]), countries_seen (string[])
- times_seen (integer): total encounters
- first_seen_at (datetime), updated_at (datetime)

**UserInput** - User-provided values for partial recon runs (custom subdomains, IPs, etc.)
- id (string, UUID): unique identifier
- input_type (string): "subdomains", "ips", "urls", "domains"
- values (string[]): user-provided values
- tool_id (string): which tool was run (e.g. "SubdomainDiscovery")
- status (string): "running", "completed", "error"
- stats (string): JSON with run statistics
- created_at (datetime), completed_at (datetime)

## Relationships

### Infrastructure Relationships
- `(d:Domain)-[:HAS_USER_INPUT]->(ui:UserInput)` - Domain has user-provided partial recon input
- `(ui:UserInput)-[:PRODUCED]->(s:Subdomain)` - Partial recon run produced this subdomain
- `(ui:UserInput)-[:PRODUCED]->(i:IP)` - Partial recon run produced this IP
- `(d:Domain)-[:HAS_EXTERNAL_DOMAIN]->(ed:ExternalDomain)` - Domain encountered foreign domain during recon
- `(s:Subdomain)-[:BELONGS_TO]->(d:Domain)` - Subdomain belongs to Domain
- `(s:Subdomain)-[:RESOLVES_TO {record_type, first_seen, last_seen}]->(i:IP)` - Subdomain resolves to IP (DNS); OTX passive_dns adds first_seen/last_seen to this relationship
- `(i:IP)-[:HAS_PORT]->(p:Port)` - IP has open Port
- `(p:Port)-[:RUNS_SERVICE]->(svc:Service)` - Port runs Service
- `(i:IP)-[:HAS_TRACEROUTE]->(tr:Traceroute)` - IP has network route data
- `(i:IP)-[:HAS_CERTIFICATE]->(c:Certificate)` - IP has TLS certificate (GVM, Censys, or FOFA)

### OTX Threat Intelligence Relationships
- `(d:Domain)-[:HISTORICALLY_RESOLVED_TO {first_seen, last_seen, record_type}]->(i:IP)` - Domain has historically resolved to this IP (from OTX domain/passive_dns)
- `(i:IP)-[:APPEARS_IN_PULSE]->(tp:ThreatPulse)` - IP appears in OTX threat pulse
- `(d:Domain)-[:APPEARS_IN_PULSE]->(tp:ThreatPulse)` - Domain appears in OTX threat pulse
- `(i:IP)-[:ASSOCIATED_WITH_MALWARE]->(m:Malware)` - IP is associated with malware sample
- `(d:Domain)-[:ASSOCIATED_WITH_MALWARE]->(m:Malware)` - Domain is associated with malware sample

### Web Application Relationships
- `(svc:Service)-[:SERVES_URL]->(b:BaseURL)` - Service serves BaseURL (from httpx probe)
- `(s:Subdomain)-[:HAS_BASE_URL]->(b:BaseURL)` - Subdomain has BaseURL (fallback when no Service link, e.g. port 80 redirected)
- `(b:BaseURL)-[:HAS_ENDPOINT]->(e:Endpoint)` - BaseURL has Endpoint
- `(e:Endpoint)-[:HAS_PARAMETER]->(param:Parameter)` - Endpoint has Parameter

### Technology Relationships
- `(b:BaseURL)-[:USES_TECHNOLOGY]->(t:Technology)` - BaseURL uses Technology (from httpx/wappalyzer)
- `(svc:Service)-[:USES_TECHNOLOGY]->(t:Technology)` - Service uses Technology (from Nmap -sV, e.g. ftp service -> vsftpd/2.3.4)
- `(p:Port)-[:HAS_TECHNOLOGY]->(t:Technology)` - Port has Technology (from Nmap -sV)
- `(p:Port)-[:USES_TECHNOLOGY]->(t:Technology)` - Port uses Technology (from GVM detection)
- `(i:IP)-[:USES_TECHNOLOGY]->(t:Technology)` - IP uses Technology (OS-level tech from GVM, no port)
- `(t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE)` - Technology has known CVE (from NVD lookup or Nmap NSE)

### Security Relationships
- `(b:BaseURL)-[:HAS_HEADER]->(h:Header)` - BaseURL has Header
- `(b:BaseURL)-[:HAS_CERTIFICATE]->(cert:Certificate)` - BaseURL has Certificate
- `(b:BaseURL)-[:HAS_SECRET]->(s:Secret)` - BaseURL has discovered Secret
- `(s:Subdomain)-[:HAS_DNS_RECORD]->(dns:DNSRecord)` - Subdomain has DNSRecord

### Vulnerability Relationships (CRITICAL DISTINCTION!)

**DAST/Web Vulnerabilities (source="nuclei"):**
- `(v:Vulnerability)-[:FOUND_AT]->(e:Endpoint)` - Vuln found at web endpoint
- `(v:Vulnerability)-[:AFFECTS_PARAMETER]->(param:Parameter)` - Vuln affects parameter

**Nmap NSE Vulnerabilities (source="nmap_nse"):**
- `(v:Vulnerability)-[:AFFECTS]->(p:Port)` - NSE vuln affects port (e.g. ftp-vsftpd-backdoor -> Port:21)
- `(v:Vulnerability)-[:FOUND_ON]->(t:Technology)` - NSE vuln found on technology (e.g. ftp-vsftpd-backdoor -> vsftpd/2.3.4)
- `(v:Vulnerability)-[:HAS_CVE]->(c:CVE)` - NSE vuln has specific CVE (e.g. -> CVE-2011-2523)

**Network/GVM Vulnerabilities (source="gvm" or "security_check"):**
- `(i:IP)-[:HAS_VULNERABILITY]->(v:Vulnerability)` - IP has network vuln
- `(s:Subdomain)-[:HAS_VULNERABILITY]->(v:Vulnerability)` - Subdomain has network vuln
- `(bu:BaseURL)-[:HAS_VULNERABILITY]->(v:Vulnerability)` - BaseURL has security check vuln
- `(d:Domain)-[:HAS_VULNERABILITY]->(v:Vulnerability)` - Domain has vuln (fallback)
- `(t:Technology)-[:HAS_VULNERABILITY]->(v:Vulnerability)` - Technology has GVM vuln
- `(p:Port)-[:HAS_VULNERABILITY]->(v:Vulnerability)` - Port has GVM vuln (no tech detected)

**WAF Bypass:**
- `(s:Subdomain)-[:WAF_BYPASS_VIA]->(i:IP)` - Subdomain can bypass WAF via direct IP

**NOTE:** Vulnerability nodes store CVE IDs as properties (`cves` list for nuclei, `cve_ids` list for GVM), NOT as relationships to CVE nodes. To find CVEs for a vulnerability, use the property: `v.cves` or `v.cve_ids`.

**CVE → MITRE Chain (from Technology CVE lookup, NOT from Vulnerability nodes):**
- `(c:CVE)-[:HAS_CWE]->(m:MitreData)` - CVE has CWE weakness
- `(m:MitreData)-[:HAS_CAPEC]->(cap:Capec)` - CWE has CAPEC attack pattern

### TruffleHog Secret Scanner Relationships
- `(d:Domain)-[:HAS_TRUFFLEHOG_SCAN]->(ts:TrufflehogScan)` - Domain has TruffleHog scan
- `(ts:TrufflehogScan)-[:HAS_REPOSITORY]->(tr:TrufflehogRepository)` - Scan scanned repository
- `(tr:TrufflehogRepository)-[:HAS_FINDING]->(tf:TrufflehogFinding)` - Repository has secret finding

### JS Recon Relationships (hierarchical: parent -> file -> findings)
- `(b:BaseURL)-[:HAS_JS_FILE]->(jf:JsReconFinding {finding_type: 'js_file'})` - BaseURL has analyzed JS file (pipeline crawl)
- `(d:Domain)-[:HAS_JS_FILE]->(jf:JsReconFinding {finding_type: 'js_file'})` - Domain has analyzed JS file (uploaded files)
- `(jf:JsReconFinding {finding_type: 'js_file'})-[:HAS_JS_FINDING]->(f:JsReconFinding)` - File has finding (dep confusion, DOM sink, etc.)
- `(jf:JsReconFinding {finding_type: 'js_file'})-[:HAS_SECRET]->(s:Secret)` - File has secret (source='js_recon')
- `(jf:JsReconFinding {finding_type: 'js_file'})-[:HAS_ENDPOINT]->(e:Endpoint)` - File has endpoint (source='js_recon')

### Gvm Exploitation Relationships
- `(e:ExploitGvm)-[:EXPLOITED_CVE]->(c:CVE)` - GVM confirmed exploitation of CVE (only connection)

### Attack Chain Relationships (Intra-chain — sequential flow - Critical: Direction Matters!)
- `(ac:AttackChain)-[:HAS_STEP {{order: N}}]->(s:ChainStep)` - Chain contains step (only first step)
- `(s1:ChainStep)-[:NEXT_STEP]->(s2:ChainStep)` - Sequential step ordering
- `(s:ChainStep)-[:PRODUCED]->(f:ChainFinding)` - Step produced a finding
- `(s:ChainStep)-[:FAILED_WITH]->(fl:ChainFailure)` - Step failed with error
- `(s:ChainStep)-[:LED_TO]->(d:ChainDecision)` - Step led to a decision
- `(d:ChainDecision)-[:DECISION_PRECEDED]->(s:ChainStep)` - Decision preceded this next step (connects decision into the flow)

### Attack Chain Bridge Relationships (Chain → Recon graph)
Note: Bridge relationships are only created for tool-execution steps. Steps using `query_graph` (read-only graph queries) do NOT create bridges.
- `(ac:AttackChain)-[:CHAIN_TARGETS]->(d:Domain)` - Chain targets domain (always)
- `(ac:AttackChain)-[:CHAIN_TARGETS]->(i:IP)` - Chain targets IP (when objective mentions IP)
- `(ac:AttackChain)-[:CHAIN_TARGETS]->(sub:Subdomain)` - Chain targets hostname (when objective mentions hostname)
- `(ac:AttackChain)-[:CHAIN_TARGETS]->(p:Port)` - Chain targets port (when objective mentions port)
- `(ac:AttackChain)-[:CHAIN_TARGETS]->(c:CVE)` - Chain targets CVE (when objective mentions CVE IDs)
- `(s:ChainStep)-[:STEP_TARGETED]->(i:IP)` - Step targeted an IP (when primary_target is an IP)
- `(s:ChainStep)-[:STEP_TARGETED]->(sub:Subdomain)` - Step targeted a hostname (when primary_target is a hostname)
- `(s:ChainStep)-[:STEP_TARGETED]->(p:Port)` - Step targeted a port
- `(s:ChainStep)-[:STEP_EXPLOITED]->(c:CVE)` - Step exploited a CVE
- `(s:ChainStep)-[:STEP_IDENTIFIED]->(t:Technology)` - Step identified a technology (case-insensitive match)
- `(f:ChainFinding)-[:FOUND_ON]->(i:IP)` - Finding relates to IP (when related_ips value is an IP)
- `(f:ChainFinding)-[:FOUND_ON]->(sub:Subdomain)` - Finding relates to hostname (when related_ips value is a hostname)
- `(f:ChainFinding)-[:FINDING_RELATES_CVE]->(c:CVE)` - Finding relates to CVE
- `(f:ChainFinding)-[:CREDENTIAL_FOR]->(svc:Service)` - Credential found for service

## Common Query Patterns

### ALL Vulnerabilities (BOTH Vulnerability and CVE nodes!)
When user asks "what vulnerabilities exist?" - query BOTH node types with UNION:
```cypher
// Get ALL security issues - both scanner findings AND known CVEs
MATCH (v:Vulnerability)
RETURN 'Vulnerability' as type, v.id as id, v.name as name, v.severity as severity, v.source as source
UNION ALL
MATCH (c:CVE)
RETURN 'CVE' as type, c.id as id, c.id as name, c.severity as severity, c.source as source
LIMIT 50
```

### Finding Scanner Vulnerabilities (Vulnerability nodes only)
```cypher
// All critical scanner findings
MATCH (v:Vulnerability)
WHERE v.severity = "critical"
RETURN v.name, v.source, v.cvss_score
LIMIT 20

// Web vulnerabilities on specific subdomain (via Service chain or direct HAS_BASE_URL)
MATCH (s:Subdomain {{name: "api.example.com"}})-[:RESOLVES_TO]->(:IP)-[:HAS_PORT]->(:Port)-[:RUNS_SERVICE]->(:Service)-[:SERVES_URL]->(b:BaseURL)
MATCH (b)-[:HAS_ENDPOINT]->(e:Endpoint)<-[:FOUND_AT]-(v:Vulnerability)
WHERE v.severity IN ["critical", "high"]
RETURN e.url, v.name, v.severity

// Network vulnerabilities on IP
MATCH (i:IP)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WHERE v.source = "gvm" AND v.severity = "high"
RETURN i.address, v.name, v.cvss_score
```

### Finding CVEs (Known vulnerabilities from NVD)
```cypher
// All CVEs in the system
MATCH (c:CVE)
RETURN c.id, c.severity, c.cvss, c.description
LIMIT 20

// High severity CVEs
MATCH (c:CVE)
WHERE c.severity IN ["HIGH", "CRITICAL"] OR c.cvss >= 7.0
RETURN c.id, c.severity, c.cvss
LIMIT 20

// CVEs linked to detected technologies
MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE)
WHERE c.cvss >= 7.0
RETURN t.name, t.version, c.id, c.severity, c.cvss
```

### Infrastructure Overview
```cypher
// All subdomains for a domain with HTTP status
MATCH (s:Subdomain)-[:BELONGS_TO]->(d:Domain {{name: "example.com"}})
RETURN s.name, s.status, s.status_codes
ORDER BY s.status

// Live subdomains (status code 2xx)
MATCH (s:Subdomain)-[:BELONGS_TO]->(d:Domain {{name: "example.com"}})
WHERE s.status STARTS WITH '2'
RETURN s.name, s.status, s.http_live_url_count

// 404 subdomains (potential subdomain takeover candidates)
MATCH (s:Subdomain {{status: "404"}})-[:BELONGS_TO]->(d:Domain {{name: "example.com"}})
RETURN s.name, s.status_codes

// Forbidden subdomains (403 — may be bypassable)
MATCH (s:Subdomain {{status: "403"}})-[:BELONGS_TO]->(d:Domain {{name: "example.com"}})
RETURN s.name, s.status_codes

// Server error subdomains (5xx — misconfigured backends)
MATCH (s:Subdomain)-[:BELONGS_TO]->(d:Domain {{name: "example.com"}})
WHERE s.status STARTS WITH '5'
RETURN s.name, s.status, s.status_codes

// Subdomain status distribution
MATCH (s:Subdomain)-[:BELONGS_TO]->(d:Domain {{name: "example.com"}})
RETURN s.status, count(s) AS count ORDER BY count DESC

// Open ports on subdomains
MATCH (s:Subdomain)-[:BELONGS_TO]->(d:Domain)
MATCH (s)-[:RESOLVES_TO]->(i:IP)
MATCH (i)-[:HAS_PORT]->(p:Port)
WHERE p.state = "open"
RETURN s.name, i.address, p.number, p.protocol
```

### Nmap Service Detection & NSE Vulnerabilities
```cypher
// All services detected by Nmap with versions
MATCH (p:Port)
WHERE p.nmap_scanned = true AND p.product IS NOT NULL
RETURN p.number, p.product, p.version, p.cpe

// Nmap NSE vulnerabilities with CVEs
MATCH (v:Vulnerability {{source: "nmap_nse"}})-[:HAS_CVE]->(c:CVE)
RETURN v.name, v.port_number, c.id, v.state

// Full Nmap attack chain: Service -> Technology -> CVE
MATCH (svc:Service)-[:USES_TECHNOLOGY]->(t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE)
RETURN svc.name, svc.port_number, t.name, c.id

// NSE vulns with the technology they affect
MATCH (v:Vulnerability {{source: "nmap_nse"}})-[:FOUND_ON]->(t:Technology)
OPTIONAL MATCH (v)-[:HAS_CVE]->(c:CVE)
RETURN v.name, t.name, c.id, v.severity
```

### Network Topology
```cypher
// Traceroute to target IP
MATCH (i:IP)-[:HAS_TRACEROUTE]->(tr:Traceroute)
RETURN i.address, tr.scanner_ip, tr.distance, tr.hops
```

### Secrets Discovered in Web Resources
```cypher
// High-severity secrets found in JS files
MATCH (b:BaseURL)-[:HAS_SECRET]->(s:Secret)
WHERE s.severity IN ["high", "critical"]
RETURN b.url, s.secret_type, s.source_url, s.sample

// All secrets grouped by BaseURL
MATCH (b:BaseURL)-[:HAS_SECRET]->(s:Secret)
RETURN b.url, count(s) AS secret_count, collect(s.secret_type) AS types
ORDER BY secret_count DESC
```

### TruffleHog Secrets (Secrets Found in Git Repositories)
```cypher
// All TruffleHog findings (verified secrets)
MATCH (d:Domain)-[:HAS_TRUFFLEHOG_SCAN]->(ts:TrufflehogScan)-[:HAS_REPOSITORY]->(tr:TrufflehogRepository)-[:HAS_FINDING]->(tf:TrufflehogFinding)
WHERE tf.verified = true
RETURN tr.name AS repository, tf.detector_name, tf.file, tf.line, tf.redacted
LIMIT 50

// TruffleHog scan summary
MATCH (ts:TrufflehogScan)
RETURN ts.target, ts.status, ts.total_findings, ts.verified_findings, ts.repositories_scanned

// TruffleHog findings grouped by detector type
MATCH (tf:TrufflehogFinding)
RETURN tf.detector_name, count(tf) AS finding_count, sum(CASE WHEN tf.verified THEN 1 ELSE 0 END) AS verified_count
ORDER BY finding_count DESC

// TruffleHog findings in a specific repository
MATCH (tr:TrufflehogRepository)-[:HAS_FINDING]->(tf:TrufflehogFinding)
WHERE tr.name CONTAINS "repo-name"
RETURN tf.detector_name, tf.file, tf.line, tf.verified, tf.redacted
```

### JS Recon Findings
```cypher
// All analyzed JS files
MATCH (file:JsReconFinding {finding_type: 'js_file'})
RETURN file.title as filename, file.source_url as url, file.is_uploaded as uploaded

// All findings from a specific JS file
MATCH (file:JsReconFinding {finding_type: 'js_file'})-[:HAS_JS_FINDING]->(jf:JsReconFinding)
WHERE file.title CONTAINS 'app.js'
RETURN jf.finding_type, jf.severity, jf.title, jf.detail
ORDER BY CASE jf.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END

// Dependency confusion findings (critical)
MATCH (file:JsReconFinding {finding_type: 'js_file'})-[:HAS_JS_FINDING]->(jf:JsReconFinding {finding_type: 'dependency_confusion'})
RETURN file.title as js_file, jf.title, jf.detail, jf.evidence

// Secrets found in JS files (traverses file hierarchy)
MATCH (file:JsReconFinding {finding_type: 'js_file'})-[:HAS_SECRET]->(s:Secret)
RETURN file.title as js_file, s.secret_type, s.sample, s.severity, s.validation_status

// JS-extracted endpoints per file
MATCH (file:JsReconFinding {finding_type: 'js_file'})-[:HAS_ENDPOINT]->(e:Endpoint)
RETURN file.title as js_file, e.method, e.path, e.category, e.endpoint_type
```

### ALL Secrets (Web + Git Repository + JS Recon + Uploads)
When user asks about "secrets" broadly, query Secret nodes (from JS file nodes and BaseURL), TrufflehogFinding nodes, AND JsReconFinding nodes:
```cypher
// Combined view of all secrets from all sources
MATCH (b:BaseURL)-[:HAS_SECRET]->(s:Secret)
RETURN 'Web Resource' as source, s.secret_type as type, s.source as tool, s.source_url as location, s.severity as severity
UNION ALL
MATCH (file:JsReconFinding {finding_type: 'js_file'})-[:HAS_SECRET]->(s:Secret)
RETURN 'JS File: ' + file.title as source, s.secret_type as type, s.source as tool, s.source_url as location, s.severity as severity
UNION ALL
MATCH (tf:TrufflehogFinding)
RETURN 'Git Repository' as source, tf.detector_name as type, 'trufflehog' as tool, tf.repository + '/' + tf.file as location, CASE WHEN tf.verified THEN 'high' ELSE 'medium' END as severity
UNION ALL
MATCH (jf:JsReconFinding)
WHERE jf.finding_type IN ['dependency_confusion', 'source_map_exposure', 'dom_sink']
RETURN 'JS Analysis' as source, jf.finding_type as type, 'js_recon' as tool, jf.source_url as location, jf.severity as severity
LIMIT 50
```

### CISA KEV (Known Weaponized Vulnerabilities)
```cypher
// Find vulnerabilities in the CISA Known Exploited Vulnerabilities catalog
MATCH (v:Vulnerability {cisa_kev: true})
RETURN v.name, v.severity, v.cve_ids, v.target_ip

// Find remediated vulnerabilities
MATCH (v:Vulnerability {remediated: true})
RETURN v.name, v.cve_ids
```

### GVM Confirmed Exploits
```cypher
// GVM active checks that confirmed exploitation (QoD=100)
MATCH (e:ExploitGvm)-[:EXPLOITED_CVE]->(c:CVE)
RETURN e.name, e.target_ip, c.id, e.evidence

// All confirmed compromises (GVM + agent ChainFindings)
MATCH (e:ExploitGvm)
RETURN 'GVM' as source, e.target_ip, e.cve_ids, e.evidence
UNION ALL
MATCH (f:ChainFinding {{finding_type: "exploit_success"}})
RETURN 'Agent' as source, f.target_ip, f.cve_ids, f.evidence
```

### Attack Chain History
```cypher
// All attack chains for a project
MATCH (ac:AttackChain)
RETURN ac.chain_id, ac.title, ac.status, ac.attack_path_type, ac.total_steps, ac.created_at
ORDER BY ac.created_at DESC
LIMIT 10

// Steps in a specific chain (ordered)
MATCH (ac:AttackChain {{chain_id: "session-123"}})-[:HAS_STEP]->(s:ChainStep)
RETURN s.iteration, s.phase, s.tool_name, s.success, s.output_summary
ORDER BY s.iteration

// All findings across chains
MATCH (f:ChainFinding)
WHERE f.severity IN ["critical", "high"]
RETURN f.finding_type, f.title, f.severity, f.evidence, f.chain_id
ORDER BY f.created_at DESC
LIMIT 20

// Findings and exploit successes 
MATCH (f:ChainFinding {{finding_type: "exploit_success"}})
RETURN f.target_ip, f.target_port, f.cve_ids, f.metasploit_module, f.evidence
LIMIT 20

// Failed attempts with lessons learned
MATCH (fl:ChainFailure)
RETURN fl.failure_type, fl.tool_name, fl.error_message, fl.lesson_learned, fl.chain_id
ORDER BY fl.created_at DESC
LIMIT 20

// Cross-session: what was tried against a specific IP
MATCH (s:ChainStep)-[:STEP_TARGETED]->(i:IP {{address: "10.0.0.5"}})
RETURN s.chain_id, s.tool_name, s.success, s.output_summary
ORDER BY s.created_at DESC

// Cross-session: what was tried against a specific hostname
MATCH (s:ChainStep)-[:STEP_TARGETED]->(sub:Subdomain {{name: "www.example.com"}})
RETURN s.chain_id, s.tool_name, s.success, s.output_summary
ORDER BY s.created_at DESC

// Technologies identified during attack chains
MATCH (s:ChainStep)-[:STEP_IDENTIFIED]->(t:Technology)
RETURN s.chain_id, s.tool_name, t.name, t.version
ORDER BY s.created_at DESC

// Chain with all findings and failures
MATCH (ac:AttackChain {{chain_id: "session-123"}})
OPTIONAL MATCH (ac)-[:HAS_STEP]->(s:ChainStep)-[:PRODUCED]->(f:ChainFinding)
OPTIONAL MATCH (s)-[:FAILED_WITH]->(fl:ChainFailure)
RETURN s.iteration, s.tool_name, f.title, fl.error_message
ORDER BY s.iteration

// Decisions made during a chain (with preceding/following steps)
MATCH (ac:AttackChain {{chain_id: "session-123"}})-[:HAS_STEP]->(:ChainStep)-[:NEXT_STEP*0..]->(s:ChainStep)-[:LED_TO]->(d:ChainDecision)
OPTIONAL MATCH (d)-[:DECISION_PRECEDED]->(next:ChainStep)
RETURN d.decision_type, d.from_state, d.to_state, d.reason, s.tool_name AS triggered_by, next.tool_name AS followed_by
```

### Counting and Aggregation
```cypher
// Vulnerability count by severity
MATCH (v:Vulnerability)
RETURN v.severity, count(v) as count
ORDER BY count DESC

// Technologies per subdomain
MATCH (s:Subdomain)-[:USES_TECHNOLOGY]->(t:Technology)
RETURN s.name, collect(t.name) as technologies
```

## Query Rules

1. **CRITICAL - Query BOTH Vulnerability AND CVE nodes** when user asks about "vulnerabilities":
   - Vulnerability nodes = scanner findings (nuclei, gvm, security_check)
   - CVE nodes = known CVEs linked to detected technologies
   - Use UNION ALL to combine results from both node types
2. **CRITICAL - Query Secret, TrufflehogFinding, AND JsReconFinding nodes** when user asks about "secrets":
   - Secret nodes = secrets found in live web resources (JS files, configs) via jsluice or js_recon
   - TrufflehogFinding nodes = secrets found in git repositories via TruffleHog
   - JsReconFinding nodes = non-secret JS findings (dependency confusion, source maps, DOM sinks, frameworks)
   - Use UNION ALL to combine results from all node types
3. **Always use LIMIT** to restrict results (default: 20-50)
4. **Relationship direction matters** - follow the arrows exactly as documented
5. **Use property filters** in WHERE clauses, not relationship traversals for filtering
6. **Check vulnerability source** when querying Vulnerability nodes:
   - source="nuclei" -> web/DAST vulnerabilities (FOUND_AT, AFFECTS_PARAMETER)
   - source="nmap_nse" -> Nmap NSE script findings (AFFECTS Port, FOUND_ON Technology, HAS_CVE CVE)
   - source="gvm" -> network vulnerabilities (HAS_VULNERABILITY from IP/Subdomain)
   - source="security_check" -> DNS/email security checks (SPF, DMARC)
   - source="netlas" -> passive CVE detection via NVD (HAS_VULNERABILITY from Service)
7. **Case sensitivity**:
   - Vulnerability.severity is lowercase: "critical", "high", "medium", "low"
   - CVE.severity is uppercase: "CRITICAL", "HIGH", "MEDIUM", "LOW"
8. **Do NOT include user_id/project_id filters** - they are injected automatically

## Output Format
Generate ONLY valid Cypher queries. No explanations, no markdown formatting.
"""


# =============================================================================
# DEEP THINK PROMPTS
# =============================================================================

DEEP_THINK_PROMPT = """You are a senior penetration testing strategist performing deep analysis before acting.

## Context
- **Phase**: {current_phase}
- **Objective**: {objective}
- **Attack Path**: {attack_path_type}
- **Iteration**: {iteration}/{max_iterations}
- **Trigger**: {trigger_reason}

## Phase Framework
{phase_definitions}

## Attack Path Strategy
{attack_path_behavior}

## Known Target Information
{target_info}

## Attack Chain Progress
{chain_context}

## Objective History
{objective_history}

## Current Task List
{todo_list}
{session_config}
{roe_section}
## Your Task

Perform a deep, structured analysis of the current situation. Consider ALL possible attack vectors, evaluate trade-offs, and produce a clear action plan. Factor in the payload/tunnel configuration, Rules of Engagement constraints, and completed objectives when planning. Be concise but thorough.

Output valid JSON matching this exact schema:
{{
    "situation_assessment": "Brief summary of what we know and where we stand",
    "attack_vectors_identified": ["vector1", "vector2", "..."],
    "recommended_approach": "The chosen strategy and WHY it's the best path forward",
    "priority_order": ["step1", "step2", "step3", "..."],
    "risks_and_mitigations": "What could go wrong and how to handle it"
}}
"""


DEEP_THINK_SECTION = """
## Deep Think

The following deep analysis was performed at a key decision point. Use it to guide your strategy:

{deep_think_result}

Follow this analysis unless new information invalidates it. If the situation has fundamentally changed, note it in your thought.
"""

DEEP_THINK_SELF_REQUEST_INSTRUCTION = """
### Deep Think Self-Request

You have Deep Think (strategic reasoning) enabled. If at any point you feel you are:
- **Stuck or going in circles** — repeating similar tools without new results
- **Not making meaningful progress** — tools succeed but yield no actionable findings
- **Unsure which vector to pursue** — multiple options and no clear winner
- **Hitting a wall** — tried several approaches and none worked

...then set `"need_deep_think": true` in your JSON output. This will trigger a strategic re-evaluation on the next iteration to help you pivot or refocus.

Example:
```json
{{
    "thought": "...",
    "reasoning": "...",
    "action": "use_tool",
    "need_deep_think": true,
    ...
}}
```
"""


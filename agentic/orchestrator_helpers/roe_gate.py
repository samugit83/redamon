"""The one pre-dispatch gate every agent executor asks before running a tool:
the Rules of Engagement, then the recon budget.

Three executor paths run tools: the single-tool node (execute_tool_node), the
plan-wave node (execute_plan_node), and every fireteam member, whose graph
reuses those same two nodes (fireteam_member_graph.py). Each calls
`check_tool_call` and refuses the call when it returns a Refusal. A rule
enforced on one path only is no rule: the agent simply takes the other path.
agentic/tests/test_roe_gate.py drives every path and fails if one stops asking.

The gate also looks through `job_spawn` at the tool it would start, for the
same reason the executor checks a spawned tool's phase: otherwise a forbidden
tool runs as a background job.

Right after it, every executor asks `check_unasked_call` (async: it may ask the
webapp): a dangerous call the project runs without confirmation still needs the
run's person to hold what the confirmation would have checked.
"""

from __future__ import annotations

from dataclasses import dataclass

# What forbidding a category refuses. Every name must be a TOOL_REGISTRY key, or
# the category silently refuses nothing (test_roe_gate.py). proxy_brain replays
# and fuzzes captured requests, so both categories that cover active attack
# traffic name it.
CATEGORY_TOOL_MAP = {
    'brute_force': ['execute_hydra', 'execute_wpscan', 'execute_ffuf', 'proxy_brain'],
    'dos': [],
    'social_engineering': [],
    'exploitation': ['metasploit_console', 'execute_hydra', 'proxy_brain'],
}

PHASE_ORDER = {'informational': 0, 'exploitation': 1, 'post_exploitation': 2}

# The discovery/scanning family the recon budget refuses once informational
# recon has used up its iterations. TOOL_REGISTRY has no field that marks a
# discovery tool, so this is a hand list; every name must be a registry key
# (test_roe_gate.py).
#
# graph_schema and graph_summary are DELIBERATELY absent, and must stay absent.
# An agent that has spent its recon budget still needs to orient before it
# commits, and neither returns target data or emits a single packet: one is a
# static code-derived document, the other a count per label. Gating them would
# block the very step this budget exists to force.
RECON_DISCOVERY_TOOLS = frozenset({
    'web_search', 'query_graph', 'shodan', 'google_dork',
    'execute_httpx', 'execute_ffuf', 'execute_nuclei', 'execute_katana',
    'execute_gau', 'execute_arjun', 'execute_wpscan', 'execute_nmap',
    'execute_subfinder', 'execute_naabu', 'execute_amass', 'execute_jsluice',
})


@dataclass(frozen=True)
class Refusal:
    """A refused tool call: `message` is what the agent reads as the tool's
    output, `error` the step's short error_message."""
    message: str
    error: str


def _dispatched_tools(tool_name: str, tool_args) -> list[str]:
    names = [tool_name]
    if tool_name == 'job_spawn' and isinstance(tool_args, dict):
        target = tool_args.get('tool_name')
        if isinstance(target, str) and target:
            names.append(target)
    return names


def roe_block_reason(tool_name: str, phase: str) -> str | None:
    """The Rules of Engagement verdict for one tool: a refusal message, or None."""
    from project_settings import get_setting

    if not get_setting('ROE_ENABLED', False):
        return None

    forbidden = set(get_setting('ROE_FORBIDDEN_TOOLS', []))
    for cat in get_setting('ROE_FORBIDDEN_CATEGORIES', []):
        forbidden.update(CATEGORY_TOOL_MAP.get(cat, []))

    if not get_setting('ROE_ALLOW_ACCOUNT_LOCKOUT', False):
        forbidden.add('execute_hydra')
    if not get_setting('ROE_ALLOW_DOS', False):
        forbidden.update(CATEGORY_TOOL_MAP.get('dos', []))

    if tool_name in forbidden:
        return f"RoE BLOCKED: Tool '{tool_name}' is forbidden by the Rules of Engagement."

    max_phase = get_setting('ROE_MAX_SEVERITY_PHASE', 'post_exploitation')
    if PHASE_ORDER.get(phase, 0) > PHASE_ORDER.get(max_phase, 2):
        return f"RoE BLOCKED: Current phase '{phase}' exceeds maximum allowed phase '{max_phase}'."

    return None


def recon_budget_block_reason(tool_name: str, phase: str, iteration: int) -> str | None:
    """The agent must not grind reconnaissance forever.

    Once informational recon exceeds its iteration budget, refuse the discovery
    family so the agent is forced to COMMIT: switch to the vulnerability class
    the live evidence already implies and move to exploitation. Every other tool
    (curl, kali_shell, code, fs_*) stays available, and switch_skill,
    transition_phase, complete and ask_user are actions, not tools, so the
    control path out of recon is never blocked.
    """
    from project_settings import get_setting

    if phase != 'informational' or not get_setting('RECON_BUDGET_GATE_ENABLED', True):
        return None
    recon_budget = get_setting('RECON_MAX_INFORMATIONAL_ITERS', 15)
    if iteration < recon_budget or tool_name not in RECON_DISCOVERY_TOOLS:
        return None
    return (
        f"RECON BUDGET EXCEEDED ({iteration} informational iterations; limit "
        f"{recon_budget}). Discovery/scanning tools are DISABLED in the "
        f"informational phase past this budget — you already have enough surface "
        f"data. STOP scanning and COMMIT now: (1) emit action='switch_skill' to "
        f"the vulnerability class the live evidence implies (path_traversal for a "
        f"file/include parameter, sql_injection for a query parameter, xss for "
        f"reflected input, ssrf for a URL fetcher, rce for a template/command "
        f"sink, brute_force_credential_guess for a login), then (2) emit "
        f"action='transition_phase' to exploitation and exploit what you can "
        f"already see. Blocked tool: {tool_name}."
    )


def check_tool_call(tool_name: str, tool_args, phase: str, iteration: int) -> Refusal | None:
    """Every executor's pre-dispatch check: a Refusal, or None to run the tool."""
    names = _dispatched_tools(tool_name, tool_args)
    for name in names:
        reason = roe_block_reason(name, phase)
        if reason:
            return Refusal(message=reason, error=reason)
    for name in names:
        reason = recon_budget_block_reason(name, phase, iteration)
        if reason:
            return Refusal(message=reason, error='recon budget exceeded')
    return None


async def check_unasked_call(tool_name: str, tool_args) -> Refusal | None:
    """A dangerous call with REQUIRE_TOOL_CONFIRMATION off: nobody confirms it, so the run's
    person must hold `agent:approve_dangerous`, as the confirmation would have asked
    (decision_check.authorize_unasked). With confirmations on, whoever confirmed the call was
    checked when they answered."""
    from project_settings import get_setting, is_dangerous_call

    if get_setting('REQUIRE_TOOL_CONFIRMATION', True) or not is_dangerous_call(tool_name, tool_args):
        return None
    from decision_check import UNAVAILABLE, authorize_unasked

    check = await authorize_unasked("tool_confirmation", "agent:approve_dangerous")
    if check.allowed:
        return None
    if check.code == UNAVAILABLE:
        return Refusal(
            message=(f"REFUSED: '{tool_name}' was not run. This project runs dangerous tools without "
                     "asking, so RedAmon checks that the person running the agent may run them, and it "
                     "could not check now. Do not retry it at once; continue with tools that are not "
                     "dangerous."),
            error="decision check unavailable")
    return Refusal(
        message=(f"REFUSED: '{tool_name}' was not run. It is a dangerous tool, and the person running "
                 f"the agent does not hold {check.permission or 'agent:approve_dangerous'} on this "
                 "project. Do not call dangerous tools again in this run: continue with tools that are "
                 "not dangerous, or report that someone who holds the permission must run this step."),
        error="permission required")

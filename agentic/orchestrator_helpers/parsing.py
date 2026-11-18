"""LLM response parsing helpers for the orchestrator."""

import json
import re
import logging
from typing import Optional, Tuple

from state import LLMDecision, OutputAnalysis, ExtractedTargetInfo, ToolPlan
from .json_utils import extract_json, repair_trailing_json_delimiters

logger = logging.getLogger(__name__)


def _normalize_extracted_info(extracted: dict) -> None:
    """
    Normalize extracted_info fields in-place so they match ExtractedTargetInfo schema.

    Handles common LLM deviations:
    - services: List[str] but LLM may return List[dict] with service_name/port/protocol keys
    - sessions: List[int] but LLM may return List[str] like "Session 1 opened..."
    """
    # Normalize services: convert dicts to strings
    if "services" in extracted and isinstance(extracted["services"], list):
        normalized = []
        for item in extracted["services"]:
            if isinstance(item, str):
                normalized.append(item)
            elif isinstance(item, dict):
                # Extract service name, optionally with port/protocol
                name = item.get("service_name") or item.get("name") or item.get("service") or ""
                port = item.get("port")
                protocol = item.get("protocol")
                if name and port:
                    normalized.append(f"{name}/{port}/{protocol}" if protocol else f"{name}/{port}")
                elif name:
                    normalized.append(name)
                else:
                    normalized.append(str(item))
            else:
                normalized.append(str(item))
        extracted["services"] = normalized

    # Normalize sessions: extract ints from strings
    if "sessions" in extracted and isinstance(extracted["sessions"], list):
        parsed_sessions = []
        for item in extracted["sessions"]:
            if isinstance(item, int):
                parsed_sessions.append(item)
            elif isinstance(item, str):
                match = re.search(r'[Ss]ession\s+(\d+)', item)
                if match:
                    parsed_sessions.append(int(match.group(1)))
                else:
                    try:
                        parsed_sessions.append(int(item))
                    except ValueError:
                        pass
        extracted["sessions"] = parsed_sessions


def _normalize_chain_findings(output_analysis: dict) -> None:
    """Normalize chain_findings in output_analysis dict in-place.

    Ensures chain_findings is a list with properly-typed fields.
    """
    findings = output_analysis.get("chain_findings")
    if findings is None:
        return
    if not isinstance(findings, list):
        output_analysis["chain_findings"] = []
        return

    VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
    normalized = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        # One id given as a bare string, or a null text field, would fail the
        # whole decision's validation, not just this entry.
        if isinstance(f.get("related_finding_ids"), str):
            f["related_finding_ids"] = [f["related_finding_ids"]]
        for key in ("title", "evidence"):
            if key in f and f[key] is None:
                f[key] = ""
        # Map alternative field names the LLM may use
        if "type" in f and "finding_type" not in f:
            f["finding_type"] = f.pop("type")
        if "detail" in f and "title" not in f:
            f["title"] = f.pop("detail")
        if "description" in f and "title" not in f:
            f["title"] = f.pop("description")
        if "name" in f and "title" not in f:
            f["title"] = f.pop("name")
        # Skip findings with no meaningful title, unless the entry names the
        # recon finding(s) it proves: then the ids ARE the finding, and dropping
        # the entry silently lost proven leads in the route exposure campaign.
        if not str(f.get("title") or "").strip() and not str(f.get("evidence") or "").strip():
            ids = [i for i in (f.get("related_finding_ids") or []) if isinstance(i, str) and i.strip()]
            if not ids:
                continue
            f["title"] = f"{f.get('finding_type') or 'finding'}: {', '.join(ids)}"
        # Normalize finding_type to lowercase
        if "finding_type" in f:
            f["finding_type"] = str(f["finding_type"]).lower().strip()
        # Default missing severity, normalize to lowercase
        sev = str(f.get("severity", "info")).lower().strip()
        f["severity"] = sev if sev in VALID_SEVERITIES else "info"
        # Ensure list fields
        if "related_cves" in f and not isinstance(f["related_cves"], list):
            f["related_cves"] = []
        if "related_ips" in f and not isinstance(f["related_ips"], list):
            f["related_ips"] = []
        # Ensure confidence is int
        try:
            f["confidence"] = int(f.get("confidence", 80))
        except (ValueError, TypeError):
            f["confidence"] = 80
        normalized.append(f)
    output_analysis["chain_findings"] = normalized


# What each action needs before the router acts on it (``AgentOrchestrator._route_after_think``):
# without it, a use_tool with no tool or a plan_tools with no plan ends the run in
# generate_response. ``action`` defaults to use_tool, as in LLMDecision.
_ACTION_NEEDS = {
    "use_tool": "tool_name", "plan_tools": "tool_plan", "deploy_fireteam": "fireteam_plan",
    "transition_phase": "phase_transition", "ask_user": "user_question", "switch_skill": "skill_switch",
    "complete": None,
}


def _complete_for_its_action(data) -> bool:
    action = data.get("action", "use_tool") if isinstance(data, dict) else None
    if not isinstance(action, str) or action not in _ACTION_NEEDS:
        return False
    need = _ACTION_NEEDS[action]
    if need is None:
        return True
    value = data.get(need)
    if need == "tool_name":
        return isinstance(value, str) and bool(value.strip())
    if need in ("tool_plan", "fireteam_plan"):
        # The checks try_parse_llm_decision downgrades a plan for: a step without a tool, a
        # member without a name or a task.
        items, keys = (("steps", ("tool_name",)) if need == "tool_plan" else ("members", ("name", "task")))
        listed = value.get(items) if isinstance(value, dict) else None
        return isinstance(listed, list) and any(isinstance(i, dict) and all(i.get(k) for k in keys) for i in listed)
    return isinstance(value, dict) and bool(value)


def _loads_first_object(json_str: str):
    """``json.loads``, except that a first object complete for its own action, followed by more (a
    second object, a note, a brace in prose), is the decision: the rest is model text, so only its
    length is logged. A first object that is only part of a decision (its tool, plan or question
    follows in the next one), or an element of a list (a comma or a closing bracket follows),
    raises the "Extra data" error as before, and the think node asks again. Anything else that
    does not parse raises as ``json.loads`` does."""
    try:
        return json.loads(json_str)
    except json.JSONDecodeError as exc:
        if exc.msg != "Extra data":
            raise
        data, end = json.JSONDecoder().raw_decode(json_str)
        if json_str[end:].lstrip()[:1] in (",", "]") or not _complete_for_its_action(data):
            raise
    logger.warning("Used the first JSON object of the LLM response; ignored %d trailing character(s)",
                   len(json_str) - end)
    return data


def try_parse_llm_decision(response_text: str) -> Tuple[Optional[LLMDecision], Optional[str]]:
    """
    Attempt to parse LLM decision from JSON response.

    Returns:
        (decision, None) on success, or (None, error_message) on failure.
    """
    try:
        json_str = extract_json(response_text)
        if not json_str:
            return None, "No JSON object found in response"

        # Pre-process JSON to handle empty nested objects that would fail validation
        # LLM sometimes outputs empty objects like user_question: {} or phase_transition: {}
        try:
            data = _loads_first_object(json_str)
        except json.JSONDecodeError as original_error:
            repaired_json = repair_trailing_json_delimiters(json_str)
            if not repaired_json:
                raise
            try:
                data = json.loads(repaired_json)
            except json.JSONDecodeError:
                # Preserve the original diagnostic when trailing delimiters
                # were not the complete cause of the malformed response.
                raise original_error
            logger.warning(
                "Recovered LLM JSON response by appending %d trailing delimiter(s)",
                len(repaired_json) - len(json_str),
            )

        # Remove empty user_question object (would fail validation due to required fields)
        if "user_question" in data and (not data["user_question"] or data["user_question"] == {}):
            data["user_question"] = None

        # Remove empty phase_transition object
        if "phase_transition" in data and (not data["phase_transition"] or data["phase_transition"] == {}):
            data["phase_transition"] = None

        # Remove empty skill_switch object
        if "skill_switch" in data and (not data["skill_switch"] or data["skill_switch"] == {}):
            data["skill_switch"] = None

        # Handle empty output_analysis object
        if "output_analysis" in data and (not data["output_analysis"] or data["output_analysis"] == {}):
            data["output_analysis"] = None

        # Handle empty tool_plan object
        if "tool_plan" in data and (not data["tool_plan"] or data["tool_plan"] == {}):
            data["tool_plan"] = None

        # Handle empty fireteam_plan object
        if "fireteam_plan" in data and (not data["fireteam_plan"] or data["fireteam_plan"] == {}):
            data["fireteam_plan"] = None

        # Validate fireteam_plan when action is deploy_fireteam
        if data.get("action") == "deploy_fireteam":
            plan = data.get("fireteam_plan")
            if not plan or not isinstance(plan, dict):
                logger.warning("action=deploy_fireteam with malformed/missing fireteam_plan; downgrading to use_tool")
                data["action"] = "use_tool"
                data["fireteam_plan"] = None
            else:
                members = plan.get("members") or []
                valid_members = [
                    m for m in members
                    if isinstance(m, dict) and m.get("name") and m.get("task")
                ]
                if not valid_members:
                    logger.warning("fireteam_plan has no valid members; downgrading to use_tool")
                    data["action"] = "use_tool"
                    data["fireteam_plan"] = None
                else:
                    plan["members"] = valid_members

        # NOTE: action=switch_skill with a missing/empty skill_switch is left
        # as-is. skill_switch is Optional so model_validate still succeeds
        # (skill_switch=None); the think_node dispatch branch handles None by
        # rejecting with feedback and looping back to think — which keeps the
        # agent alive rather than dropping it into the fallback complete() path.

        # Validate tool_plan when action is plan_tools
        if data.get("action") == "plan_tools" and data.get("tool_plan"):
            plan = data["tool_plan"]
            steps = plan.get("steps", [])
            if not steps:
                # Downgrade to use_tool if plan is empty
                data["action"] = "use_tool"
                data["tool_plan"] = None
                logger.warning("Empty tool_plan steps, downgrading to use_tool")
            else:
                # Ensure each step has a tool_name
                valid_steps = [s for s in steps if isinstance(s, dict) and s.get("tool_name")]
                if not valid_steps:
                    data["action"] = "use_tool"
                    data["tool_plan"] = None
                    logger.warning("No valid steps in tool_plan, downgrading to use_tool")
                else:
                    plan["steps"] = valid_steps

        # Normalize combined_summary → interpretation in output_analysis
        if (data.get("output_analysis") and
                isinstance(data["output_analysis"], dict) and
                "combined_summary" in data["output_analysis"] and
                "interpretation" not in data["output_analysis"]):
            data["output_analysis"]["interpretation"] = data["output_analysis"].pop("combined_summary")

        # Pre-process extracted_info fields in output_analysis (same as parse_analysis_response)
        if (data.get("output_analysis") and
                isinstance(data["output_analysis"], dict) and
                "extracted_info" in data["output_analysis"]):
            extracted = data["output_analysis"]["extracted_info"]
            _normalize_extracted_info(extracted)

        # chain_findings is a field OF output_analysis, but a model analysing a
        # single tool's output often puts it beside output_analysis (the prompt's
        # example for that case shows it as a separate fragment). LLMDecision
        # ignores unknown top-level keys, so every finding there vanished
        # silently, confirmations included: move it rather than drop it.
        top_findings = data.pop("chain_findings", None)
        if isinstance(top_findings, list) and top_findings:
            if not isinstance(data.get("output_analysis"), dict):
                data["output_analysis"] = {}
            nested = data["output_analysis"].get("chain_findings")
            data["output_analysis"]["chain_findings"] = (nested if isinstance(nested, list) else []) + top_findings

        # Normalize chain_findings in output_analysis
        if data.get("output_analysis") and isinstance(data["output_analysis"], dict):
            _normalize_chain_findings(data["output_analysis"])

        return LLMDecision.model_validate(data), None
    except json.JSONDecodeError as e:
        return None, f"Invalid JSON: {e}"
    except Exception as e:
        return None, f"Validation error: {e}"


def parse_llm_decision(response_text: str) -> LLMDecision:
    """Parse LLM decision from JSON response (backward-compatible wrapper)."""
    decision, error = try_parse_llm_decision(response_text)
    if decision:
        return decision

    logger.warning(f"Failed to parse LLM decision: {error}")
    return LLMDecision(
        thought=response_text,
        reasoning="Failed to parse structured response",
        action="complete",
        completion_reason="Unable to continue due to response parsing error",
        updated_todo_list=[],
    )


def parse_analysis_response(response_text: str) -> OutputAnalysis:
    """Parse analysis response from LLM using Pydantic validation."""
    try:
        json_str = extract_json(response_text)
        if json_str:
            data = json.loads(json_str)

            # Normalize extracted_info fields (services, sessions, etc.)
            if "extracted_info" in data and isinstance(data["extracted_info"], dict):
                _normalize_extracted_info(data["extracted_info"])

            return OutputAnalysis.model_validate(data)
    except Exception as e:
        logger.warning(f"Failed to parse analysis response: {type(e).__name__}: {e}")

    # Fallback - extract fields from JSON if possible, even when validation fails
    fallback_interpretation = response_text
    fallback_findings = []
    fallback_next_steps = []

    try:
        json_str = extract_json(response_text)
        if json_str:
            data = json.loads(json_str)
            if "interpretation" in data:
                fallback_interpretation = data["interpretation"]
            if "actionable_findings" in data and isinstance(data["actionable_findings"], list):
                fallback_findings = data["actionable_findings"]
            if "recommended_next_steps" in data and isinstance(data["recommended_next_steps"], list):
                fallback_next_steps = data["recommended_next_steps"]
    except Exception:
        # If JSON extraction also fails, strip markdown code blocks from raw text
        # Remove ```json ... ``` wrapper
        fallback_interpretation = re.sub(r'^```(?:json)?\s*', '', fallback_interpretation)
        fallback_interpretation = re.sub(r'\s*```$', '', fallback_interpretation)
        fallback_interpretation = fallback_interpretation.strip()

    return OutputAnalysis(
        interpretation=fallback_interpretation,
        extracted_info=ExtractedTargetInfo(),
        actionable_findings=fallback_findings,
        recommended_next_steps=fallback_next_steps,
    )

"""Phase-related helpers for the orchestrator."""

import json
import asyncio
import logging
from typing import List, Optional, Tuple

from pydantic import ValidationError
from langchain_core.messages import SystemMessage, HumanMessage

from state import AttackPathClassification
from prompts.classification import build_classification_prompt
from .json_utils import normalize_content, extract_json
from .llm_retry import RateLimitWaiter, ainvoke_through_rate_limits, heal_llm_param_error
from agent_in_the_loop.purpose import llm_purpose

logger = logging.getLogger(__name__)


async def classify_attack_path(
    llm,
    objective: str,
    max_retries: int = 3
) -> Tuple[str, str, Optional[str], Optional[int], List[str]]:
    """
    Use LLM to classify the attack path type, required phase, and target hints.

    Returns validated AttackPathType using Pydantic model.
    Includes retry logic with exponential backoff for resilience.

    Args:
        llm: The LLM instance to use for classification
        objective: User's objective/request text
        max_retries: Maximum number of retry attempts (default: 3)

    Returns:
        Tuple of (attack_path_type, required_phase, target_host, target_port, target_cves):
        - attack_path_type: "cve_exploit", "brute_force_credential_guess", "phishing_social_engineering", "denial_of_service", or "<term>-unclassified"
        - required_phase: "informational", "exploitation", or "post_exploitation"
        - target_host: IP or hostname extracted from objective (or None)
        - target_port: port number extracted from objective (or None)
        - target_cves: list of CVE IDs extracted from objective
    """
    prompt = build_classification_prompt(objective)
    logger.debug(f"Classification prompt ({len(prompt)} chars):\n{prompt}")

    messages = [
        SystemMessage(content="You are an attack path classifier. Output only valid JSON."),
        HumanMessage(content=prompt)
    ]

    last_error = None
    healed: set[str] = set()
    # Its 100 ms backoff suits a bad answer, not a full rate-limit window; one
    # waiter for every attempt keeps that wait bounded.
    rate_limits = RateLimitWaiter("classify attack path")

    for attempt in range(max_retries):
        try:
            with llm_purpose("classify", attempt=attempt):
                response = await ainvoke_through_rate_limits(llm, messages, waiter=rate_limits)
            json_str = extract_json(normalize_content(response.content))

            if json_str:
                data = json.loads(json_str)
                classification = AttackPathClassification.model_validate(data)

                # Use LLM-determined required_phase from classification
                required_phase = classification.required_phase

                logger.info(
                    f"Attack path classified as '{classification.attack_path_type}' "
                    f"(confidence: {classification.confidence:.2f}, "
                    f"service: {classification.detected_service}, "
                    f"required_phase: {required_phase}, "
                    f"target_host: {classification.target_host}, "
                    f"target_port: {classification.target_port}, "
                    f"target_cves: {classification.target_cves}, "
                    f"attempt: {attempt + 1})"
                )

                if classification.attack_path_type.endswith("-unclassified"):
                    logger.info(
                        f"Unclassified attack path: '{classification.attack_path_type}' "
                        f"— no specific workflow prompts will be used"
                    )

                return (
                    classification.attack_path_type,
                    required_phase,
                    classification.target_host,
                    classification.target_port,
                    classification.target_cves,
                )
            else:
                last_error = "No valid JSON found in response"
                logger.warning(f"Attempt {attempt + 1}/{max_retries}: {last_error}")

        except json.JSONDecodeError as e:
            last_error = f"JSON decode error: {e}"
            logger.warning(f"Attempt {attempt + 1}/{max_retries}: {last_error}")

        except ValidationError as e:
            last_error = f"Pydantic validation error: {e}"
            logger.warning(f"Attempt {attempt + 1}/{max_retries}: {last_error}")

        except Exception as e:
            if getattr(e, "no_retry", False):
                # An Agent in the Loop step that was not answered: asking again
                # would wait for the same absent driver. Take the safe default.
                last_error = f"not retried: {type(e).__name__}"
                logger.warning(f"Attempt {attempt + 1}/{max_retries}: {last_error}")
                break
            # Self-heal (once per param): the model may reject our default
            # `temperature`/`reasoning_effort` with a permanent 400 (OpenAI
            # o-series, Bedrock Claude 4.x, Moonshot k3, GLM/Qwen thinking, ...).
            # This call site runs its own loop instead of retry_llm_call, so heal
            # here too and retry immediately rather than burning attempts on an
            # error that will repeat identically.
            heal = heal_llm_param_error(llm, e, already_healed=frozenset(healed))
            if heal is not None:
                llm, heal_key = heal
                healed.add(heal_key)
                logger.warning(
                    f"Attempt {attempt + 1}/{max_retries}: model rejected "
                    f"`{heal_key}`; retrying without it."
                )
                continue
            last_error = f"Unexpected error: {e}"
            logger.warning(f"Attempt {attempt + 1}/{max_retries}: {last_error}")

        # Exponential backoff before retry (100ms, 200ms, 400ms)
        if attempt < max_retries - 1:
            await asyncio.sleep(0.1 * (2 ** attempt))

    logger.error(f"Failed to classify attack path after {max_retries} attempts: {last_error}")
    return "cve_exploit", "informational", None, None, []  # Safe default - start with recon


def determine_phase_for_new_objective(
    required_phase: str,
    current_phase: str,
) -> str:
    """
    Determine appropriate phase for new objective based on LLM-classified required_phase.

    Per user preference:
    - Auto-downgrade to informational (no approval needed)
    - Require approval for exploitation/post-exploitation upgrades

    Args:
        required_phase: The LLM-classified required phase (from classify_attack_path)
        current_phase: The current phase before this objective

    Returns:
        The phase to transition to for this objective
    """
    # SAFE AUTO-TRANSITION: Downgrade to informational without approval
    if required_phase == "informational" and current_phase in ["exploitation", "post_exploitation"]:
        logger.info("Auto-downgrading phase to informational for new objective (no approval needed)")
        return "informational"

    # Keep current phase if already there (avoid redundant transitions)
    if required_phase == current_phase:
        logger.info(f"Staying in {current_phase} phase for new objective")
        return current_phase

    # For exploitation/post-exploitation: stay in informational and let agent request with approval
    if required_phase in ["exploitation", "post_exploitation"]:
        logger.info(f"New objective needs {required_phase}, starting in informational (agent will request transition)")
        return "informational"

    # Default to informational (safest)
    return "informational"

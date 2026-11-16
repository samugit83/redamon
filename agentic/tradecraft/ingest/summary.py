"""Stage ``summary``: the text the agent reads to decide when to use a resource (§4.6).

1.x's single call and prompt, with its numbers as settings: ``summary.targetTokens`` (300
reads "250-350 tokens", 1.x's range), ``summary.homepageChars`` (6,000) and ``summary.titles``
(50), plus the person's ``summary.extraInstructions``. A PDF is summarised from its first five
pages, as in 1.x. The start page and the titles are wrapped as untrusted content.

A hand-written or locked summary is kept (no call is made). The call is made once: a failure
keeps the previous summary and counts its error code in the report (TD-20, no retry).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from agent_in_the_loop.purpose import llm_purpose
from orchestrator_helpers.json_utils import normalize_content
from prompt_safety import UNTRUSTED_OUTPUT_GUIDANCE, wrap_untrusted
from tradecraft.ingest.crawl import error_code_of

if TYPE_CHECKING:
    from tradecraft.ingest.pipeline import IngestState

PDF_SUMMARY_PAGES = 5


def system_prompt(target_tokens: int, extra: str = "") -> str:
    low, high = max(50, target_tokens - 50), target_tokens + 50
    prompt = (
        "You are summarizing a security-knowledge website so an autonomous "
        f"pentest agent can decide when to consult it. Output {low}-{high} tokens.\n"
        "Mention: domains covered (web, AD, cloud, mobile, ...), structure "
        "(per-CVE, per-payload, per-technique), and the kinds of pentest queries "
        "it answers best. No marketing language. No first person.\n\n"
        + UNTRUSTED_OUTPUT_GUIDANCE
    )
    if extra.strip():
        prompt += "\n\nInstructions from the person who added this resource:\n" + extra.strip()
    return prompt


def user_message(url: str, site_type: str, body: str, titles: list[str], homepage_chars: int, n_titles: int) -> str:
    sample = "\n  - ".join(t[:80] for t in titles[:n_titles] if t)
    return (
        f"URL: {url}\n"
        f"Detected type: {site_type}\n\n"
        f"Homepage / README excerpt (first {homepage_chars} chars):\n"
        + wrap_untrusted((body or "")[:homepage_chars], "WEB_CONTENT") + "\n\n"
        + f"Sample page titles from sitemap (first {n_titles}):\n"
        + wrap_untrusted("  - " + sample, "WEB_CONTENT") + "\n"
    )


def keeps_previous(state: "IngestState") -> bool:
    resource = state.request.resource
    return resource.summary_locked or resource.summary_source == "manual"


def source_text(state: "IngestState") -> str:
    if state.site_type == "pdf":
        pages = [e.extra.get("text") or "" for e in state.entries[:PDF_SUMMARY_PAGES]]
        return "\n\n".join(pages)
    return state.home.text if state.home is not None else ""


async def summarize(state: "IngestState") -> "IngestState":
    """Sets ``state.summary`` to the new text, or leaves it None to keep the previous one."""
    if keeps_previous(state):
        return state
    s = state.settings
    body = source_text(state)
    titles = [e.title for e in state.entries if e.extra.get("status", "kept") == "kept"]
    if not body and not titles:
        return state
    try:
        llm = await state.model()
    except Exception as exc:
        state.count_error(error_code_of(exc))
        return state
    if llm is None:
        return state
    messages = [
        {"role": "system", "content": system_prompt(s.int("summary.targetTokens"), s.str("summary.extraInstructions"))},
        {"role": "user", "content": user_message(state.url, state.site_type, body, titles,
                                                 s.int("summary.homepageChars"), s.int("summary.titles"))},
    ]
    state.llm_calls += 1
    try:
        with llm_purpose("tradecraft_ingest", step="summary"):
            resp = await llm.ainvoke(messages)
    except Exception as exc:
        state.count_error(error_code_of(exc))
        return state
    text = normalize_content(getattr(resp, "content", "") or "").strip()
    if text:
        state.summary = text
    else:
        state.count_error("summary_empty")
    return state


def summary_update(state: "IngestState") -> Optional[str]:
    return None if keeps_previous(state) else state.summary

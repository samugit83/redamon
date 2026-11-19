"""The route classifier (plan §8.4): one model call, JSON out, one repair attempt."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from navigator import prompts
from navigator.limits import ROUTES
from navigator.text import message_text

_JSON_RE = re.compile(r"\{.*\}", re.S)
_LANG_RE = re.compile(r"^[a-z]{2}$")


@dataclass
class RouteDecision:
    routes: list[str]
    standalone_question: str
    language: str = "en"
    action_request: bool = False
    #: Routes the model picked that this person may not use: route -> reason code.
    refused: dict[str, str] = field(default_factory=dict)
    #: The model's output could not be read: one general specialist with every allowed tool.
    fallback: bool = False


def parse_decision(text: str) -> Optional[dict]:
    m = _JSON_RE.search(text or "")
    if not m:
        return None
    try:
        data = json.loads(m.group(0))
    except ValueError:
        return None
    if not isinstance(data, dict) or not isinstance(data.get("routes"), list):
        return None
    return data


def decide(data: Optional[dict], message: str, allowed: list[str], reasons: dict[str, str]) -> RouteDecision:
    if data is None:
        return RouteDecision([r for r in allowed if r != "direct"], message, fallback=True)
    picked = []
    for r in data.get("routes") or []:
        if isinstance(r, str) and r in ROUTES and r not in picked:
            picked.append(r)
    refused = {r: reasons.get(r, "not_allowed") for r in picked if r not in allowed}
    routes = [r for r in picked if r in allowed]
    if len(routes) > 1 and "direct" in routes:
        routes.remove("direct")
    if not routes:
        routes = ["direct"]
    question = data.get("standalone_question")
    question = question.strip()[:4000] if isinstance(question, str) and question.strip() else message
    lang = data.get("language")
    lang = lang.lower() if isinstance(lang, str) and _LANG_RE.match(lang.lower()) else "en"
    return RouteDecision(routes, question, lang, data.get("action_request") is True, refused)


def router_messages(history: list[dict], message: str, allowed: list[str], page_path: Optional[str]) -> list:
    routes = "\n".join(f"- {r}: {prompts.ROUTE_DESCRIPTIONS[r]}" for r in ROUTES)
    system = prompts.ROUTER.format(routes=routes, allowed=", ".join(allowed) or "none")
    convo = []
    for turn in history[-6:]:
        who = "User" if turn["role"] == "user" else "AI Navigator"
        convo.append(f"{who}: {turn['content'][:600]}")
    where = f"\n(The user is on the screen {page_path}.)" if page_path else ""
    human = ("Conversation so far:\n" + "\n".join(convo) + "\n\n" if convo else "") + f"Latest message:{where}\n{message}"
    return [SystemMessage(system), HumanMessage(human)]


async def route_message(llm, config, history, message, allowed, reasons, page_path, checkpoint) -> RouteDecision:
    messages = router_messages(history, message, allowed, page_path)
    await checkpoint()
    first = await llm.ainvoke(messages, config=config)
    data = parse_decision(message_text(first.content))
    if data is None:
        await checkpoint()
        repair = messages + [AIMessage(message_text(first.content)[:2000]),
                             HumanMessage("Answer with the JSON object only, exactly in the format asked.")]
        second = await llm.ainvoke(repair, config=config)
        data = parse_decision(message_text(second.content))
    return decide(data, message, allowed, reasons)

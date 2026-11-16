"""Stage ``tree`` (T2.3): the resource's folders, or virtual topics, with page counts and a
one-line description each (Q4 item 5, R-334).

Writes ``state.tree`` as [{path, parent_path, label, page_count, description, kind}]. Folders
come from the cards' breadcrumbs (the GitHub folders, else the URL path under the resource's
own), so a folder's path is its breadcrumb joined with ``/`` plus a final ``/`` and a page
sits in the folder its breadcrumb names; ``page_count`` counts the kept pages at and below it.

A flat resource, whose pages sit in no folder or in one folder without subfolders that holds
most of them (a blog's ``/posts/``), gets a virtual tree by topic instead (kind ``topic``): one
node per vocabulary topic its pages carry, labelled with the topic's label, and ``Other`` for
the pages without one. A PDF (its pages are listed in order) and a CVE archive (looked up by
CVE id) have no tree.

Folder descriptions are written from the titles of each folder's pages by the resource's
model: ``constants.foldersPerDescriptionCall`` folders per call, at most
``constants.folderDescriptionCalls`` calls per resource, purpose ``tradecraft_ingest``, never
retried (TD-20). The titles come from the site and go to the model as untrusted content; the
answer is one plain line per folder the call asked about, nothing else is kept.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Iterable, Optional

from agent_in_the_loop.purpose import llm_purpose
from logging_config import get_logger
from orchestrator_helpers.json_utils import normalize_content
from prompt_safety import UNTRUSTED_OUTPUT_GUIDANCE, wrap_untrusted
from tradecraft.ingest.crawl import error_code_of
from tradecraft.settings import constant
from tradecraft.vocab import load_vocab

if TYPE_CHECKING:  # the pipeline imports this module: the state is a type here only
    from tradecraft.ingest.pipeline import IngestState

logger = get_logger(__name__)

NO_TREE_TYPES = ("pdf", "cve-poc-db")
# A folder without subfolders that holds this share of the pages makes the resource flat.
FLAT_SHARE = 0.8
OTHER_LABEL = "Other"
TITLES_PER_FOLDER = 20
MAX_DESCRIPTION_CHARS = 160


def folder_path(crumbs: Iterable[str]) -> str:
    crumbs = [c for c in crumbs if c]
    return "/".join(crumbs) + "/" if crumbs else ""


def _kept(cards: list[dict]) -> list[dict]:
    return [c for c in cards if c.get("status", "kept") == "kept"]


def folder_tree(cards: list[dict]) -> list[dict]:
    """One node per folder any kept page sits in or under, ordered by path."""
    counts: dict[tuple[str, ...], int] = {}
    for card in cards:
        crumbs = tuple(c for c in card.get("breadcrumb") or () if c)
        for depth in range(1, len(crumbs) + 1):
            counts[crumbs[:depth]] = counts.get(crumbs[:depth], 0) + 1
    return [{"path": folder_path(k), "parent_path": folder_path(k[:-1]), "label": k[-1], "page_count": n,
             "description": "", "kind": "folder"} for k, n in sorted(counts.items())]


def is_flat(nodes: list[dict], pages: int) -> bool:
    if not nodes:
        return True
    parents = {n["parent_path"] for n in nodes}
    return any(n["path"] not in parents and n["page_count"] >= FLAT_SHARE * pages for n in nodes)


def topic_label(topic_id: str) -> str:
    return next((t["label"] for t in load_vocab().topics if t["id"] == topic_id), topic_id)


def topic_of_label(label: str) -> Optional[str]:
    """The topic id a virtual node's label stands for; None for ``Other`` (pages without one)."""
    return next((t["id"] for t in load_vocab().topics if t["label"] == label), None)


def topic_tree(cards: list[dict]) -> list[dict]:
    nodes = []
    for topic in load_vocab().topic_ids:
        n = sum(1 for c in cards if topic in (c.get("topics") or ()))
        if n:
            label = topic_label(topic)
            nodes.append({"path": folder_path([label]), "parent_path": "", "label": label, "page_count": n,
                          "description": "", "kind": "topic"})
    other = sum(1 for c in cards if not c.get("topics"))
    if other:
        nodes.append({"path": folder_path([OTHER_LABEL]), "parent_path": "", "label": OTHER_LABEL,
                      "page_count": other, "description": "", "kind": "topic"})
    return nodes


def titles_in(node: dict, cards: list[dict]) -> list[str]:
    if node["kind"] == "topic":
        topic = topic_of_label(node["label"])
        pages = [c for c in cards if (topic in (c.get("topics") or ()) if topic else not c.get("topics"))]
    else:
        prefix = tuple(node["path"].rstrip("/").split("/"))
        pages = [c for c in cards if tuple(c.get("breadcrumb") or ())[:len(prefix)] == prefix]
    return [" ".join(str(c.get("title", "")).split())[:80] for c in pages[:TITLES_PER_FOLDER]]


def description_prompt(batch: list[dict], cards: list[dict]) -> str:
    folders = {n["path"]: titles_in(n, cards) for n in batch}
    return (
        "You describe the folders of a security-knowledge resource for an autonomous pentest agent "
        "that browses it. For each folder, write ONE plain line of at most 15 words saying what its "
        "pages cover, judged only from the page titles listed. No first person, no marketing words.\n\n"
        + UNTRUSTED_OUTPUT_GUIDANCE + "\n\n"
        "Folders, each with sample page titles:\n"
        + wrap_untrusted(json.dumps(folders, ensure_ascii=False, indent=1), "WEB_CONTENT") + "\n\n"
        'Reply ONLY with JSON mapping each folder path to its line, e.g. {"kerberos/": "Kerberos attacks: '
        'roasting, tickets, delegation"}.'
    )


def parse_descriptions(text: str, asked: set[str]) -> Optional[dict[str, str]]:
    """The answer's lines for the folders asked about; None when it is not such a JSON object."""
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        data = json.loads(text[start:end + 1])
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    out = {}
    for path, line in data.items():
        if path in asked and isinstance(line, str):
            line = " ".join(line.split())[:MAX_DESCRIPTION_CHARS]
            if line:
                out[path] = line
    return out


async def describe(state: "IngestState", nodes: list[dict], cards: list[dict]) -> None:
    if not nodes:
        return
    try:
        llm = await state.model()
    except Exception as exc:
        state.count_error(error_code_of(exc))
        return
    if llm is None:
        return
    per_call = int(constant("foldersPerDescriptionCall"))
    max_calls = int(constant("folderDescriptionCalls"))
    for call, start in enumerate(range(0, len(nodes), per_call)):
        if call >= max_calls:
            break
        await state.check_cancelled()
        batch = nodes[start:start + per_call]
        state.llm_calls += 1
        try:
            with llm_purpose("tradecraft_ingest", step="folder_descriptions"):
                resp = await llm.ainvoke(description_prompt(batch, cards))
        except Exception as exc:
            # Never retried; the folders left keep no description.
            code = error_code_of(exc)
            state.count_error(code)
            logger.info(f"[tradecraft] job {state.request.job_id} folder_descriptions code={code}")
            return
        lines = parse_descriptions(normalize_content(getattr(resp, "content", "") or ""), {n["path"] for n in batch})
        if lines is None:
            state.count_error("folder_descriptions_invalid")
            continue
        for node in batch:
            node["description"] = lines.get(node["path"], "")


async def build(state: "IngestState") -> "IngestState":
    if state.site_type in NO_TREE_TYPES:
        return state
    cards = _kept(state.cards)
    if not cards:
        return state
    nodes = folder_tree(cards)
    if len(cards) >= 2 and is_flat(nodes, len(cards)):
        nodes = topic_tree(cards)
    await describe(state, nodes, cards)
    state.tree = nodes
    return state

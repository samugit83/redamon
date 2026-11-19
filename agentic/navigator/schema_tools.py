"""graph_labels and graph_label_schema: the graph schema, local and without data (plan §8.8)."""
from __future__ import annotations

from navigator.tooling import NavTool, ToolOutcome, as_json, refused

ROUTE = "graph"


def _labels() -> dict:
    from graph_db.schema_catalog import LABELS
    return LABELS


def label_lines() -> str:
    """One line per node label: its name and the first sentence of its description."""
    out = []
    for name, seg in sorted(_labels().items()):
        desc = " ".join(str(seg.get("description") or "").split())
        first = desc.split(". ")[0][:140]
        out.append(f"- {name}: {first}")
    return "\n".join(out)


def cypher_rules() -> str:
    """The invariant half of TEXT_TO_CYPHER_SYSTEM (label every pattern, read-only, Node IDs,
    muted findings), without the 80 KB generated schema or its output-format instruction."""
    from prompts import TEXT_TO_CYPHER_SYSTEM
    marker = "__GRAPH_SCHEMA__"
    head = TEXT_TO_CYPHER_SYSTEM.split(marker, 1)[0]
    return head.replace("You are a Neo4j Cypher query expert for a security reconnaissance database.", "").strip()


def make_schema_tools() -> list[NavTool]:
    async def graph_labels(_args: dict) -> ToolOutcome:
        return ToolOutcome(label_lines(), True, "Listed the graph's node types")

    async def graph_label_schema(args: dict) -> ToolOutcome:
        from graph_db.schema_render import render_label
        label = args.get("label")
        if not isinstance(label, str) or label not in _labels():
            return refused("unknown_label", "Unknown label; call graph_labels for the list.",
                           "Looked up a node type that does not exist")
        return ToolOutcome(render_label(label), True, f"Read the {label} node type")

    return [
        NavTool("graph_labels", "Every node label of the attack-surface graph with a one-line description. No project data.",
                {"type": "object", "properties": {}, "additionalProperties": False}, ROUTE, graph_labels),
        NavTool("graph_label_schema", "The properties and relationships of one node label. No project data.",
                {"type": "object", "properties": {"label": {"type": "string"}}, "required": ["label"],
                 "additionalProperties": False}, ROUTE, graph_label_schema),
    ]


__all__ = ["make_schema_tools", "label_lines", "cypher_rules", "as_json"]

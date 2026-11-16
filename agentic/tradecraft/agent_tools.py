"""The tools a 2.0 run calls in place of the 1.x ones (TD-10).

``tradecraft_lookup`` keeps its name and its arguments; the executor's dispatch sends a call
here when the run's catalog is 2.0 (``runtime.v2_tool_for``). Search and the librarian add
their tools in later phases.
"""

from __future__ import annotations

from typing import Optional

from langchain_core.tools import tool

from tradecraft.library import reader


@tool
async def tradecraft_lookup(
    resource_id: str,
    query: str = "",
    cve_id: Optional[str] = None,
    section_path: Optional[str] = None,
    force_refresh: bool = False,
) -> str:
    """Fetch curated exploitation tradecraft from a configured knowledge resource.

    The list of available `resource_id` slugs and what each covers is provided in the
    system prompt under TOOL_REGISTRY[tradecraft_lookup].

    Args:
        resource_id: slug of the resource (see system prompt for the catalog)
        query: free-text technique/topic
        cve_id: required when the resource is a cve-poc-db
        section_path: skip auto-pick; force a specific page or "page=N" for PDFs
        force_refresh: read a Stored resource's page from the site instead of its stored copy
    """
    return await reader.lookup(resource_id=resource_id, query=query or "", cve_id=cve_id,
                               section_path=section_path, force_refresh=bool(force_refresh))


lookup_tool = tradecraft_lookup

V2_TOOLS = {"tradecraft_lookup": lookup_tool}

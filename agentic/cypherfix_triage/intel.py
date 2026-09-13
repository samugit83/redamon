"""CVE intelligence: is it in KEV, what is its EPSS, is there a public PoC.

WHY THIS IS NOT OPTIONAL DETAIL
Without it, L — "how likely is this to be exploited" — falls back to a class
prior and the CVSS vector. That is the difference between "a remote code
execution, in CISA KEV, EPSS 0.94, exploited in the wild since Tuesday" and "a
remote code execution", and the whole point of the board is telling those two
apart.

HOW IT STAYS SAFE
- **Only CVE ids leave the machine.** They are regex-validated in code before
  the call, so nothing a scanner or a model wrote reaches the command line.
- **The tool is fixed.** Triage may call `cve_intel` and nothing else, checked
  against a one-name allowlist rather than trusted to a prompt.
- **Only numbers and booleans are kept** from the reply. vulnx returns prose
  too; storing it would put third-party text into the graph and then into
  prompts for no benefit.
- **It never raises.** vulnx being down, rate-limited or missing degrades the
  ranking to class priors, which is the documented behaviour, not an outage.

The results live on the GLOBAL CVE nodes — reference nodes with no tenant keys,
per the graph rules — so every project benefits from one lookup, and the 24-hour
TTL keeps the anonymous rate limit (10 requests a minute) comfortable.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

#: The ONLY shape allowed to leave this process as a tool argument.
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")

#: The one tool triage may call on the kali-sandbox MCP server.
ALLOWED_TOOL = "cve_intel"

#: How long a cached lookup is good for. vulnx refreshes roughly every six
#: hours; a day keeps us well inside the anonymous rate limit and means a large
#: project's second run costs nothing.
INTEL_TTL_HOURS = 24

#: CVE ids per call. vulnx takes a comma-separated list, and batching is what
#: keeps a 200-CVE project inside 10 requests a minute.
BATCH_SIZE = 25

#: Only these fields are kept from the reply, with the type each is coerced to.
KEPT_FIELDS = {
    "kev": bool,
    "epss_score": float,
    "epss_percentile": float,
    "has_poc": bool,
    "has_template": bool,
}


def valid_cve_ids(values) -> list[str]:
    """The subset of `values` that is a real CVE id, upper-cased and unique.

    This is the boundary. Anything that is not exactly a CVE id — a GHSA alias,
    a package name, an injected argument — is dropped here rather than being
    escaped later.
    """
    seen, out = set(), []
    for value in values or []:
        text = str(value or "").strip().upper()
        if CVE_ID_RE.match(text) and text not in seen:
            seen.add(text)
            out.append(text)
    return sorted(out)


def is_fresh(intel_at, now=None) -> bool:
    """Is a stored `intel_at` still inside the TTL?"""
    if not intel_at:
        return False
    text = str(intel_at)
    try:
        # Neo4j returns RFC3339 with nanoseconds; datetime wants microseconds.
        cleaned = re.sub(r"(\.\d{6})\d+", r"\1", text).replace("Z", "+00:00")
        stamp = datetime.fromisoformat(cleaned)
    except (TypeError, ValueError):
        return False
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    reference = now or datetime.now(timezone.utc)
    return reference - stamp < timedelta(hours=INTEL_TTL_HOURS)


def parse_intel(raw: str) -> dict:
    """vulnx output -> {CVE id: {kept fields}}. Never raises.

    vulnx has changed its output shape before, so this reads defensively: a
    payload it cannot understand yields nothing, and the model falls back to
    class priors rather than to wrong numbers.
    """
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError):
        # Not JSON: a human-readable table or an error message.
        return {}

    rows = []
    if isinstance(payload, dict):
        for key in ("results", "data", "vulnerabilities", "cves"):
            if isinstance(payload.get(key), list):
                rows = payload[key]
                break
        else:
            rows = [payload]
    elif isinstance(payload, list):
        rows = payload

    out: dict = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        cve_id = str(row.get("cve_id") or row.get("id") or "").strip().upper()
        if not CVE_ID_RE.match(cve_id):
            continue
        out[cve_id] = _extract(row)
    return out


def _extract(row: dict) -> dict:
    """Pull the five fields out of whatever nesting vulnx used this month."""
    def dig(*path):
        current = row
        for step in path:
            if not isinstance(current, dict):
                return None
            current = current.get(step)
        return current

    epss = dig("epss") if isinstance(dig("epss"), dict) else {}
    result = {
        "kev": bool(dig("is_kev") or dig("kev") or dig("is_exploited")),
        "epss_score": _num(epss.get("epss_score") if epss else dig("epss_score")),
        "epss_percentile": _num(
            epss.get("epss_percentile") if epss else dig("epss_percentile")),
        "has_poc": bool(dig("is_poc") or dig("poc") or dig("has_poc")),
        "has_template": bool(dig("is_template") or dig("has_template")
                             or dig("nuclei_template")),
    }
    return {k: v for k, v in result.items() if v is not None}


def _num(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return None if number != number else number


class CveIntel:
    """Fetches and caches CVE intelligence for one triage run.

    Construct, `await load(cve_ids, client)`, then read `by_cve`. A failure at
    any point leaves `by_cve` holding whatever the graph already had, which is
    the graceful degradation the score model is written to expect.
    """

    def __init__(self, pdcp_api_key: str = ""):
        self.pdcp_api_key = pdcp_api_key or ""
        self.by_cve: dict = {}
        self.refreshed = 0
        self.intel_date: str = ""

    async def load(self, cve_ids, graph_client) -> dict:
        """Read the cache, refresh what is stale, and return {cve: intel}."""
        wanted = valid_cve_ids(cve_ids)
        if not wanted:
            return {}

        cached = {}
        try:
            cached = await _read_cached(graph_client, wanted)
        except Exception as e:                                    # noqa: BLE001
            logger.warning(f"Could not read the CVE intelligence cache: {e}")

        stale = [cve for cve in wanted if not is_fresh((cached.get(cve) or {}).get("intel_at"))]
        self.by_cve = {cve: dict(row) for cve, row in cached.items()}

        if stale:
            fetched = await self._fetch(stale)
            if fetched:
                self.by_cve.update(fetched)
                self.refreshed = len(fetched)
                try:
                    await _write_cached(graph_client, fetched)
                except Exception as e:                            # noqa: BLE001
                    logger.warning(f"Could not store CVE intelligence: {e}")

        if self.by_cve:
            self.intel_date = datetime.now(timezone.utc).isoformat()
        return self.by_cve

    async def _fetch(self, cve_ids: list) -> dict:
        """Call vulnx through the kali-sandbox MCP server, in batches."""
        try:
            from mcp_registry import BearerAuth, MCPServer
            from langchain_mcp_adapters.client import MultiServerMCPClient  # noqa: F401
        except Exception:                                         # noqa: BLE001
            logger.info("No MCP client available; ranking uses class priors")
            return {}

        out: dict = {}
        for start in range(0, len(cve_ids), BATCH_SIZE):
            batch = cve_ids[start:start + BATCH_SIZE]
            raw = await self._call_tool(",".join(batch))
            if not raw:
                continue
            out.update(parse_intel(raw))
        if out:
            logger.info(f"Refreshed intelligence for {len(out)} CVEs")
        return out

    async def _call_tool(self, ids_argument: str) -> str:
        """One `cve_intel` call. Never raises; returns "" on any failure."""
        # Belt and braces: the argument is rebuilt from validated ids, so this
        # can only ever be a comma-separated list of CVE ids.
        if not all(CVE_ID_RE.match(part) for part in ids_argument.split(",")):
            logger.error("Refusing a cve_intel argument that is not CVE ids")
            return ""

        try:
            from langchain_mcp_adapters.client import MultiServerMCPClient

            url = os.environ.get(
                "MCP_NETWORK_RECON_URL", "http://host.docker.internal:8000/sse")
            token = os.environ.get("MCP_AUTH_TOKEN", "")
            config = {
                "network_recon": {
                    "transport": "sse",
                    "url": url,
                    **({"headers": {"Authorization": f"Bearer {token}"}}
                       if token else {}),
                }
            }
            client = MultiServerMCPClient(config)
            tools = await client.get_tools()
            tool = next((t for t in tools if t.name == ALLOWED_TOOL), None)
            if tool is None:
                logger.info(f"{ALLOWED_TOOL} is not available on the MCP server")
                return ""
            result = await tool.ainvoke({
                "args": ids_argument,
                "api_key": self.pdcp_api_key,
            })
            return str(result or "")
        except Exception as e:                                    # noqa: BLE001
            logger.warning(
                f"cve_intel lookup failed ({e.__class__.__name__}); "
                f"the ranking falls back to class priors")
            return ""


async def _read_cached(graph_client, cve_ids: list) -> dict:
    """What the global CVE nodes already know."""
    import asyncio

    def read():
        with graph_client.driver.session() as session:
            rows = session.run(
                """
                MATCH (c:CVE) WHERE c.id IN $ids
                RETURN c.id AS id, c.kev AS kev, c.epss_score AS epss_score,
                       c.epss_percentile AS epss_percentile, c.has_poc AS has_poc,
                       c.has_template AS has_template,
                       toString(c.intel_at) AS intel_at
                """,
                ids=cve_ids,
            )
            return {r["id"]: {k: r[k] for k in
                              ("kev", "epss_score", "epss_percentile",
                               "has_poc", "has_template", "intel_at")}
                    for r in rows}

    return await asyncio.to_thread(read)


async def _write_cached(graph_client, fetched: dict) -> None:
    """Store the intelligence on the global CVE nodes.

    MERGE without tenant keys on purpose: CVE is a shared reference node, so one
    lookup serves every project. Only the five typed fields plus a timestamp are
    written; nothing project-specific and no prose.
    """
    import asyncio

    rows = [{"id": cve, **{k: v for k, v in intel.items() if k in KEPT_FIELDS}}
            for cve, intel in fetched.items()]
    if not rows:
        return

    def write():
        with graph_client.driver.session() as session:
            session.run(
                """
                UNWIND $rows AS row
                MERGE (c:CVE {id: row.id})
                SET c.kev = coalesce(row.kev, false),
                    c.epss_score = row.epss_score,
                    c.epss_percentile = row.epss_percentile,
                    c.has_poc = coalesce(row.has_poc, false),
                    c.has_template = coalesce(row.has_template, false),
                    c.intel_at = datetime(),
                    // Every node write stamps this: the Updated column in the
                    // graph tables reads it, and a blank one looks like a node
                    // nothing has touched.
                    c.updated_at = datetime()
                """,
                rows=rows,
            )

    await asyncio.to_thread(write)

"""mimikatz_parse — parse mimikatz output into Credential graph nodes.

Agent tool. DANGEROUS: listed in ``DANGEROUS_TOOLS`` (human
approval per run) and the tool refuses to run without ``acknowledged=true``;
refusal leaves the graph untouched.

How the output gets here: mimikatz runs through the existing session path
(``metasploit_console`` / kiwi over an MSF session — ``interact_session`` in
``mcp/servers/metasploit_server.py``), the agent saves the transcript into the
workspace with ``fs_write``, and this tool parses that file. Supported
transcript formats:

  - ``sekurlsa::logonpasswords`` (per-SSP ``* NTLM`` / ``* LM`` /
    ``* cleartext`` lines under ``User Name``/``Domain`` blocks)
  - ``lsadump::sam`` (``User :`` / ``Hash NTLM:`` / ``Hash LM:`` blocks)
  - ``lsadump::dcsync`` (``SamAccountName :`` / ``Username:`` accounts with
    ``Hash NTLM:`` / ``NTLM hash:`` lines)

The parser is a PURE function (text -> list[dict]) tolerant to incomplete or
garbage input: unparseable lines are skipped and counted, never fatal.

Graph writes are tenant-scoped MERGEs (graph-db-writes rules): ``Credential``
nodes keyed by (kind, username, domain, value) + user_id + project_id — full
secret VALUES live only inside the graph and the workspace file, NEVER in the
tool response or logs, which carry counts per kind only. When ``origin_host``
names a host the graph already knows (a ``Subdomain``), a ``ORIGIN``
relationship is drawn to it; otherwise the host is kept as a node property
(the tool never invents anchor nodes).
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable, Optional

CRED_KINDS = ("ntlm", "lm", "sha1", "plaintext")

_HEX_VALUE = re.compile(r"^[0-9a-fA-F]{16,64}$")

# State-carrying line patterns, applied in order per line.
_USER_PATTERNS = [
    re.compile(r"^\s*(?:User Name|SamAccountName|Username|User)\s*:\s*(\S.*)$",
               re.IGNORECASE),
]
_DOMAIN_PATTERNS = [
    re.compile(r"^\s*(?:Domain|Logon Domain)\s*:\s*(\S.*)$", re.IGNORECASE),
    # lsadump::dcsync banner: [DC] 'corp.example.com' will be the domain
    re.compile(r"^\[DC\]\s+'([^']+)'\s+will be the domain", re.IGNORECASE),
]
_RID_PATTERN = re.compile(r"^\s*RID\s*:\s*[0-9a-fA-F]+\s*\(\s*(\d+)\s*\)")

# Hash / plaintext capture lines. Group 1 is the value.
_VALUE_PATTERNS = [
    # kind, regex
    ("ntlm", re.compile(r"^\s*\*?\s*(?:Hash NTLM|NTLM hash|NTLM)\s*:\s*([0-9a-fA-F]+)\s*$",
                        re.IGNORECASE)),
    ("lm", re.compile(r"^\s*\*?\s*(?:Hash LM|LM hash|LM|lm\s*-\s*\d+)\s*:\s*([0-9a-fA-F]+)\s*$",
                      re.IGNORECASE)),
    ("sha1", re.compile(r"^\s*\*?\s*SHA1\s*:\s*([0-9a-fA-F]+)\s*$", re.IGNORECASE)),
    ("plaintext", re.compile(r"^\s*\*?\s*(?:cleartext|Password)\s*:\s*(\S.*)$",
                             re.IGNORECASE)),
]

_EMPTY_HASHES = {
    "00000000000000000000000000000000",  # empty LM/NTLM
    "31d6cfe0d16ae931b73c59d7e0c089c0",  # empty NTLM (lowercase)
    "aad3b435b51404eeaad3b435b51404ee",  # classic empty LM
}


def parse_mimikatz(text: str) -> list[dict[str, Any]]:
    """Pure parse of a mimikatz transcript into credential dicts.

    Each credential: {kind, value, username, domain, rid}. Lines that match no
    pattern are ignored; hash values must be hex (16-64 chars) or the line is
    ignored — garbage input yields fewer credentials, never an exception.
    Duplicate (kind, value, username, domain) tuples are collapsed.
    """
    creds: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    username = ""
    domain = ""
    rid: Optional[int] = None

    for line in (text or "").splitlines():
        user_match = next((p.match(line) for p in _USER_PATTERNS if p.match(line)), None)
        if user_match:
            username = user_match.group(1).strip()
            continue
        domain_match = next((p.match(line) for p in _DOMAIN_PATTERNS if p.match(line)), None)
        if domain_match:
            domain = domain_match.group(1).strip()
            continue
        rid_match = _RID_PATTERN.match(line)
        if rid_match:
            rid = int(rid_match.group(1))
            continue
        for kind, pattern in _VALUE_PATTERNS:
            match = pattern.match(line)
            if not match:
                continue
            value = match.group(1).strip()
            if kind != "plaintext":
                if not _HEX_VALUE.match(value):
                    continue  # not a hash (e.g. "(null)" or empty markers)
                if value.lower() in _EMPTY_HASHES:
                    continue  # empty hashes carry no credential
            if not username and kind == "plaintext":
                continue  # a password with no principal is not reusable
            key = (kind, value.lower() if kind != "plaintext" else value,
                   username.lower(), domain.lower())
            if key in seen:
                continue
            seen.add(key)
            creds.append({"kind": kind, "value": value, "username": username,
                          "domain": domain, "rid": rid})
            break
    return creds


def summarize(creds: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts per kind — the ONLY shape the tool response is allowed to carry."""
    counts = {kind: 0 for kind in CRED_KINDS}
    for cred in creds:
        counts[cred["kind"]] = counts.get(cred["kind"], 0) + 1
    return {"total": len(creds), "by_kind": counts}


# ---------------------------------------------------------------------------
# Graph writes (batched, tenant-scoped, idempotent).
# ---------------------------------------------------------------------------

_MERGE_CREDENTIAL = (
    "UNWIND $rows AS row "
    "MERGE (c:Credential {kind: row.kind, username: row.username, domain: row.domain, "
    "value: row.value, user_id: $user_id, project_id: $project_id}) "
    "ON CREATE SET c.source = 'mimikatz_parse', c.updated_at = datetime() "
    "SET c.rid = row.rid, c.origin_host = $origin_host, c.updated_at = datetime()"
)

# ORIGIN attaches only to a host the graph already knows — the tool never
# MERGEs anchor nodes (no stray Subdomain/Domain from a transcript).
_MERGE_ORIGIN = (
    "UNWIND $rows AS row "
    "MATCH (c:Credential {kind: row.kind, username: row.username, domain: row.domain, "
    "value: row.value, user_id: $user_id, project_id: $project_id}) "
    "MATCH (h:Subdomain {name: $origin_host, user_id: $user_id, project_id: $project_id}) "
    "MERGE (c)-[r:ORIGIN]->(h) "
    "ON CREATE SET r.source = 'mimikatz_parse'"
)


def ingest_credentials(run_write: Callable[[str, dict], Any], user_id: str,
                       project_id: str, creds: list[dict[str, Any]],
                       origin_host: str = "", batch_size: int = 500) -> dict[str, Any]:
    rows = [
        {"kind": c["kind"], "username": c["username"], "domain": c["domain"],
         "value": c["value"], "rid": c.get("rid")}
        for c in creds
    ]
    for i in range(0, len(rows), batch_size):
        run_write(_MERGE_CREDENTIAL, {
            "rows": rows[i:i + batch_size], "user_id": user_id,
            "project_id": project_id, "origin_host": origin_host,
        })
    attached = 0
    if origin_host:
        for i in range(0, len(rows), batch_size):
            run_write(_MERGE_ORIGIN, {
                "rows": rows[i:i + batch_size], "user_id": user_id,
                "project_id": project_id, "origin_host": origin_host,
            })
            attached += len(rows[i:i + batch_size])
    summary = summarize(creds)
    summary["origin_host"] = origin_host or None
    summary["origin_edges_attempted"] = attached if origin_host else 0
    return summary


def _read_workspace_file(path: str) -> str:
    from workspace_fs import _resolve_safe

    resolved = _resolve_safe(path)
    if not resolved or not resolved.is_file():
        raise FileNotFoundError(f"no such workspace file: {path}")
    return resolved.read_text(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Tool factory.
# ---------------------------------------------------------------------------

def build_mimikatz_parse_tool() -> Any:
    from langchain_core.tools import tool

    @tool
    async def mimikatz_parse(path: str, origin_host: str = "",
                             acknowledged: bool = False) -> str:
        """Parse a saved mimikatz transcript into Credential graph nodes.

        Dangerous: requires acknowledged=true and per-run approval. Input is a
        workspace file (run mimikatz via the existing session tools and save
        the output with fs_write first). Supports sekurlsa::logonpasswords,
        lsadump::sam and lsadump::dcsync transcripts; response is counts per
        kind only — secret values stay in the graph/workspace, never here.
        """
        import json as _json

        from agent_context import current_user_id, current_project_id

        if not acknowledged:
            return _json.dumps({
                "error": "mimikatz_parse is a dangerous tool: pass acknowledged=true "
                         "to confirm this parse run (approval is also required when the "
                         "tool-confirmation gate is enabled)",
            })
        try:
            user_id = current_user_id.get()
            project_id = current_project_id.get()
            if not user_id or not project_id:
                return _json.dumps({"error": "mimikatz_parse requires an active session context"})
            text = _read_workspace_file(path)
            if not text.strip():
                return _json.dumps({"error": f"{path} is empty — nothing to parse"})
            creds = parse_mimikatz(text)
            if not creds:
                return _json.dumps({
                    "error": "no credentials recognised in the transcript",
                    "hint": "supported formats: sekurlsa::logonpasswords, "
                            "lsadump::sam, lsadump::dcsync",
                })

            import os

            from neo4j import GraphDatabase

            driver = GraphDatabase.driver(
                os.environ["NEO4J_URI"],
                auth=(os.environ.get("NEO4J_USER", "neo4j"),
                      os.environ["NEO4J_PASSWORD"]),
            )
            try:
                with driver.session() as session:
                    def run_write(cypher: str, params: dict) -> None:
                        session.run(cypher, params).consume()

                    summary = ingest_credentials(
                        run_write, user_id, project_id, creds,
                        origin_host=origin_host.strip(),
                    )
            finally:
                driver.close()
            return _json.dumps(summary)
        except (FileNotFoundError, ValueError) as exc:
            return _json.dumps({"error": str(exc)})
        except Exception as exc:  # readable error, never crash the step
            return _json.dumps({"error": f"mimikatz_parse failed: {exc}"})

    return mimikatz_parse

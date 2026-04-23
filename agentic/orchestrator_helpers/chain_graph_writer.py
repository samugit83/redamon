"""Attack Chain graph writer for Neo4j.

Persists the EvoGraph — attack chain nodes (AttackChain, ChainStep,
ChainFinding, ChainDecision, ChainFailure) and bridge relationships
to the recon graph.

All write operations are fire-and-forget: they run in a background thread
so the agent loop is never blocked.  Errors are logged but never crash
the orchestrator.

Replaces and absorbs the former exploit_writer.py.
"""

import asyncio
import logging
import re
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, SessionExpired

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Driver singleton with health check
# ---------------------------------------------------------------------------

_driver = None
_driver_lock = threading.Lock()


def _get_driver(uri: str, user: str, password: str):
    """Get or create a singleton Neo4j driver with connectivity check.

    If the cached driver's connection has gone stale (e.g. Neo4j restarted),
    it is discarded and a fresh driver is created.
    """
    global _driver
    with _driver_lock:
        if _driver is not None:
            try:
                _driver.verify_connectivity()
            except Exception:
                logger.warning("Neo4j driver connectivity check failed; recreating driver")
                try:
                    _driver.close()
                except Exception:
                    pass
                _driver = None

        if _driver is None:
            _driver = GraphDatabase.driver(uri, auth=(user, password))
        return _driver


def close_driver():
    """Close the Neo4j driver (call on shutdown)."""
    global _driver
    with _driver_lock:
        if _driver is not None:
            _driver.close()
            _driver = None


# ---------------------------------------------------------------------------
# Fire-and-forget helper with retry and dead-letter counter
# ---------------------------------------------------------------------------

_failed_write_count = 0
_failed_write_lock = threading.Lock()


def get_failed_write_count() -> int:
    """Return the cumulative count of permanently failed graph writes."""
    return _failed_write_count


def _increment_failed_writes():
    global _failed_write_count
    with _failed_write_lock:
        _failed_write_count += 1


def _run_with_retry(func, args, kwargs, max_retries, retry_delay, sync):
    """Execute func with retry logic. On final failure, increment dead-letter counter."""
    last_exc = None
    for attempt in range(1 + max_retries):
        try:
            func(*args, **kwargs)
            return  # Success
        except (ServiceUnavailable, SessionExpired, OSError) as exc:
            last_exc = exc
            if attempt < max_retries:
                logger.debug("Chain graph write transient error (attempt %d/%d): %s",
                             attempt + 1, max_retries + 1, exc)
                time.sleep(retry_delay)
        except Exception as exc:
            # Non-transient (Cypher syntax, constraint violation) — no point retrying
            last_exc = exc
            break

    _increment_failed_writes()
    label = "sync fallback" if sync else "async"
    func_name = getattr(func, "__name__", str(func))
    logger.warning(
        "Chain graph write permanently failed (%s) [%s] after %d attempt(s): %s",
        label, func_name, 1 + max_retries, last_exc,
    )


def _fire_and_forget(func, *args, max_retries: int = 1, retry_delay: float = 0.5, **kwargs):
    """Schedule *func* in a background thread; retry on transient errors, then dead-letter."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        _run_with_retry(func, args, kwargs, max_retries, retry_delay, sync=True)
        return

    async def _run():
        await loop.run_in_executor(
            None,
            lambda: _run_with_retry(func, args, kwargs, max_retries, retry_delay, sync=False),
        )

    asyncio.ensure_future(_run())


def _uid() -> str:
    return str(uuid.uuid4())


_IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')


def _looks_like_ip(value: str) -> bool:
    """Return True if *value* looks like an IPv4 address."""
    return bool(_IP_RE.match(value))


# ---------------------------------------------------------------------------
# Metasploit info extraction (absorbed from exploit_writer)
# ---------------------------------------------------------------------------

def _extract_metasploit_info(execution_trace: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract Metasploit module, payload, and commands from execution trace."""
    info: Dict[str, Any] = {
        "metasploit_module": None,
        "payload": None,
        "commands_used": [],
    }
    for step in execution_trace:
        tool_name = step.get("tool_name", "")
        tool_args = step.get("tool_args") or {}
        command = tool_args.get("command", "")
        if tool_name != "metasploit_console" or not command:
            continue
        info["commands_used"].append(command)
        use_match = re.search(r"use\s+(exploit/\S+|auxiliary/\S+)", command)
        if use_match:
            info["metasploit_module"] = use_match.group(1)
        payload_match = re.search(r"set\s+PAYLOAD\s+(\S+)", command, re.IGNORECASE)
        if payload_match:
            info["payload"] = payload_match.group(1)
    return info


def _build_exploit_report(
    attack_type: str,
    target_ip: str,
    target_port: Optional[int],
    cve_ids: Optional[List[str]],
    username: Optional[str],
    session_id: Optional[int],
    evidence: str,
    msf_info: Dict[str, Any],
) -> str:
    """Build a structured exploitation report string."""
    lines: list[str] = []
    if attack_type == "cve_exploit":
        cve_str = ", ".join(cve_ids) if cve_ids else "Unknown CVE"
        lines.append(f"Successfully exploited {cve_str} on {target_ip}")
        if target_port:
            lines.append(f"Target port: {target_port}")
        if msf_info.get("metasploit_module"):
            lines.append(f"Module: {msf_info['metasploit_module']}")
        if msf_info.get("payload"):
            lines.append(f"Payload: {msf_info['payload']}")
        if session_id is not None:
            lines.append(f"Session established: {session_id}")
    elif attack_type == "brute_force_credential_guess":
        lines.append(f"Brute force credential discovery on {target_ip}:{target_port or '?'}")
        if username:
            lines.append(f"Compromised account: {username}")
    else:
        # Unclassified or unknown attack type
        clean_type = attack_type.replace("-unclassified", "").replace("_", " ").title()
        lines.append(f"{clean_type} exploit success on {target_ip}:{target_port or '?'}")
        if cve_ids:
            lines.append(f"Related CVEs: {', '.join(cve_ids)}")
        if msf_info.get("metasploit_module"):
            lines.append(f"Module: {msf_info['metasploit_module']}")
        if username:
            lines.append(f"Compromised account: {username}")
        if session_id is not None:
            lines.append(f"Session established: {session_id}")
    if evidence:
        lines.append(f"Evidence: {evidence}")
    return "\n".join(lines)


# ===================================================================
# PUBLIC FIRE-AND-FORGET ENTRY POINTS
# Each ``fire_*`` function validates credentials, then schedules
# the actual ``_write_*`` via ``_fire_and_forget``.
# ===================================================================

# -------------------------------------------------------------------
# 1. AttackChain
# -------------------------------------------------------------------

def fire_create_attack_chain(
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    *,
    chain_id: str,
    user_id: str,
    project_id: str,
    title: str = "",
    objective: str = "",
    attack_path_type: str = "cve_exploit",
    target_host: Optional[str] = None,
    target_port: Optional[int] = None,
    target_cves: Optional[List[str]] = None,
) -> None:
    if not neo4j_uri or not neo4j_password:
        return
    _fire_and_forget(
        _write_attack_chain,
        neo4j_uri, neo4j_user, neo4j_password,
        chain_id=chain_id,
        user_id=user_id,
        project_id=project_id,
        title=title,
        objective=objective,
        attack_path_type=attack_path_type,
        target_host=target_host,
        target_port=target_port,
        target_cves=target_cves,
    )


def _write_attack_chain(
    uri, user, password,
    *,
    chain_id, user_id, project_id, title, objective,
    attack_path_type,
    target_host=None, target_port=None, target_cves=None,
):
    driver = _get_driver(uri, user, password)
    cypher = """
    MERGE (ac:AttackChain {chain_id: $chain_id})
    ON CREATE SET
        ac.user_id       = $user_id,
        ac.project_id    = $project_id,
        ac.title          = $title,
        ac.objective      = $objective,
        ac.status         = 'active',
        ac.attack_path_type = $attack_path_type,
        ac.total_steps    = 0,
        ac.successful_steps = 0,
        ac.failed_steps   = 0,
        ac.phases_reached = [],
        ac.created_at     = datetime(),
        ac.updated_at     = datetime()
    ON MATCH SET
        ac.updated_at     = datetime()
    // --- Specific target bridges (only ONE is created) ---
    // Priority: IP > Subdomain > Port > CVE > Domain (fallback)
    WITH ac
    OPTIONAL MATCH (ip:IP {address: $target_host, user_id: $user_id, project_id: $project_id})
    FOREACH (_ IN CASE WHEN ip IS NOT NULL THEN [1] ELSE [] END |
        MERGE (ac)-[:CHAIN_TARGETS]->(ip))
    WITH ac
    OPTIONAL MATCH (sub:Subdomain {name: $target_host, user_id: $user_id, project_id: $project_id})
    FOREACH (_ IN CASE WHEN sub IS NOT NULL THEN [1] ELSE [] END |
        MERGE (ac)-[:CHAIN_TARGETS]->(sub))
    WITH ac
    OPTIONAL MATCH (:IP {user_id: $user_id, project_id: $project_id})-[:HAS_PORT]->(p:Port {number: $target_port})
    WHERE $target_port IS NOT NULL
    FOREACH (_ IN CASE WHEN p IS NOT NULL THEN [1] ELSE [] END |
        MERGE (ac)-[:CHAIN_TARGETS]->(p))
    WITH ac
    UNWIND (CASE WHEN size($target_cves) > 0 THEN $target_cves ELSE [null] END) AS cve_id
    OPTIONAL MATCH (c:CVE {id: cve_id, user_id: $user_id, project_id: $project_id})
    FOREACH (_ IN CASE WHEN c IS NOT NULL THEN [1] ELSE [] END |
        MERGE (ac)-[:CHAIN_TARGETS]->(c))
    // Fallback: Domain when no CHAIN_TARGETS was actually created
    WITH ac
    OPTIONAL MATCH (ac)-[:CHAIN_TARGETS]->(existing)
    WITH ac, count(existing) AS num_targets
    WHERE num_targets = 0
    OPTIONAL MATCH (d:Domain {user_id: $user_id, project_id: $project_id})
    FOREACH (_ IN CASE WHEN d IS NOT NULL THEN [1] ELSE [] END |
        MERGE (ac)-[:CHAIN_TARGETS]->(d))
    """
    with driver.session() as session:
        session.run(cypher, {
            "chain_id": chain_id,
            "user_id": user_id,
            "project_id": project_id,
            "title": title or "",
            "objective": objective or "",
            "attack_path_type": attack_path_type or "",
            "target_host": target_host or "",
            "target_port": target_port,
            "target_cves": target_cves or [],
        })
    logger.info("[%s/%s] AttackChain MERGE: %s (target: %s)", user_id, project_id, chain_id, target_host)


# -------------------------------------------------------------------
# 2. ChainStep
# -------------------------------------------------------------------

def fire_record_step(
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    *,
    step_id: str,
    chain_id: str,
    prev_step_id: Optional[str],
    user_id: str,
    project_id: str,
    iteration: int,
    phase: str,
    tool_name: str,
    tool_args_summary: str = "",
    thought: str = "",
    reasoning: str = "",
    output_summary: str = "",
    output_analysis: str = "",
    success: bool = True,
    error_message: Optional[str] = None,
    duration_ms: Optional[int] = None,
    extracted_info: Optional[dict] = None,
    agent_id: str = "root",
    agent_name: str = "root",
    fireteam_id: Optional[str] = None,
) -> None:
    if not neo4j_uri or not neo4j_password:
        return
    _fire_and_forget(
        _write_step,
        neo4j_uri, neo4j_user, neo4j_password,
        step_id=step_id,
        chain_id=chain_id,
        prev_step_id=prev_step_id,
        user_id=user_id,
        project_id=project_id,
        iteration=iteration,
        phase=phase,
        tool_name=tool_name,
        tool_args_summary=tool_args_summary,
        thought=thought,
        reasoning=reasoning,
        output_summary=output_summary,
        output_analysis=output_analysis,
        success=success,
        error_message=error_message,
        duration_ms=duration_ms,
        extracted_info=extracted_info,
        agent_id=agent_id,
        agent_name=agent_name,
        fireteam_id=fireteam_id,
    )


def sync_record_step(
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    *,
    step_id: str,
    chain_id: str,
    prev_step_id: Optional[str],
    user_id: str,
    project_id: str,
    iteration: int,
    phase: str,
    tool_name: str,
    tool_args_summary: str = "",
    thought: str = "",
    reasoning: str = "",
    output_summary: str = "",
    output_analysis: str = "",
    success: bool = True,
    error_message: Optional[str] = None,
    duration_ms: Optional[int] = None,
    extracted_info: Optional[dict] = None,
    agent_id: str = "root",
    agent_name: str = "root",
    fireteam_id: Optional[str] = None,
) -> None:
    """Write ChainStep synchronously (blocking).

    Use instead of fire_record_step when subsequent fire-and-forget writes
    (findings, failures) depend on the step existing in Neo4j.
    """
    if not neo4j_uri or not neo4j_password:
        return
    try:
        _write_step(
            neo4j_uri, neo4j_user, neo4j_password,
            step_id=step_id,
            chain_id=chain_id,
            prev_step_id=prev_step_id,
            user_id=user_id,
            project_id=project_id,
            iteration=iteration,
            phase=phase,
            tool_name=tool_name,
            tool_args_summary=tool_args_summary,
            thought=thought,
            reasoning=reasoning,
            output_summary=output_summary,
            output_analysis=output_analysis,
            success=success,
            error_message=error_message,
            duration_ms=duration_ms,
            extracted_info=extracted_info,
            agent_id=agent_id,
            agent_name=agent_name,
            fireteam_id=fireteam_id,
        )
    except Exception as exc:
        logger.error("Chain graph step write failed (sync): %s", exc)


def _write_step(
    uri, user, password,
    *,
    step_id, chain_id, prev_step_id,
    user_id, project_id, iteration, phase,
    tool_name, tool_args_summary, thought, reasoning,
    output_summary, output_analysis, success, error_message,
    duration_ms, extracted_info,
    agent_id="root", agent_name="root", fireteam_id=None,
):
    driver = _get_driver(uri, user, password)

    # Main step node (always created)
    cypher = """
    MERGE (s:ChainStep {step_id: $step_id})
    ON CREATE SET
        s.chain_id          = $chain_id,
        s.user_id           = $user_id,
        s.project_id        = $project_id,
        s.iteration         = $iteration,
        s.phase             = $phase,
        s.tool_name         = $tool_name,
        s.tool_args_summary = $tool_args_summary,
        s.thought           = $thought,
        s.reasoning         = $reasoning,
        s.output_summary    = $output_summary,
        s.output_analysis   = $output_analysis,
        s.success           = $success,
        s.error_message     = $error_message,
        s.duration_ms       = $duration_ms,
        s.agent_id          = $agent_id,
        s.agent_name        = $agent_name,
        s.fireteam_id       = $fireteam_id,
        s.created_at        = datetime()
    """
    params = {
        "step_id": step_id,
        "chain_id": chain_id,
        "user_id": user_id,
        "project_id": project_id,
        "iteration": iteration,
        "phase": phase or "",
        "tool_name": tool_name or "",
        "tool_args_summary": tool_args_summary or "",
        "thought": thought or "",
        "reasoning": reasoning or "",
        "output_summary": output_summary or "",
        "output_analysis": output_analysis or "",
        "success": success,
        "error_message": error_message,
        "duration_ms": duration_ms,
        "agent_id": agent_id or "root",
        "agent_name": agent_name or "root",
        "fireteam_id": fireteam_id,
    }

    with driver.session() as session:
        session.run(cypher, params)

        # Only the first step links to AttackChain (no prev = first step)
        if not prev_step_id:
            session.run(
                """
                MATCH (ac:AttackChain {chain_id: $chain_id})
                MATCH (s:ChainStep {step_id: $step_id})
                MERGE (ac)-[:HAS_STEP]->(s)
                """,
                {"chain_id": chain_id, "step_id": step_id},
            )

        # Link to previous step: either through a decision or directly
        if prev_step_id:
            # Check if previous step has a ChainDecision attached
            result = session.run(
                """
                MATCH (prev:ChainStep {step_id: $prev_id})-[:LED_TO]->(d:ChainDecision)
                RETURN d.decision_id AS did
                LIMIT 1
                """,
                {"prev_id": prev_step_id},
            )
            has_decision = result.single() is not None

            if has_decision:
                # Route through the decision: decision -> current step
                session.run(
                    """
                    MATCH (prev:ChainStep {step_id: $prev_id})-[:LED_TO]->(d:ChainDecision)
                    MATCH (curr:ChainStep {step_id: $curr_id})
                    MERGE (d)-[:DECISION_PRECEDED]->(curr)
                    """,
                    {"prev_id": prev_step_id, "curr_id": step_id},
                )
            else:
                # Direct sequential link
                session.run(
                    """
                    MATCH (prev:ChainStep {step_id: $prev_id})
                    MATCH (curr:ChainStep {step_id: $curr_id})
                    MERGE (prev)-[:NEXT_STEP]->(curr)
                    """,
                    {"prev_id": prev_step_id, "curr_id": step_id},
                )

        # Bridge relationships (skip for query_graph — it only reads existing data)
        if tool_name != "query_graph":
            _resolve_step_bridges(session, step_id, extracted_info or {}, user_id, project_id)

    logger.debug("[%s/%s] ChainStep recorded: iter=%d tool=%s", user_id, project_id, iteration, tool_name)


def fire_resolve_step_bridges(
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    *,
    step_id: str,
    extracted_info: dict,
    user_id: str,
    project_id: str,
    tool_name: str = "",
) -> None:
    """Fire-and-forget: resolve (ChainStep)-[:STEP_*]->(recon node) edges
    for a previously-written ChainStep.

    Used by callers (notably fireteam_member_think_node) that wrote the
    ChainStep before the output-analysis LLM call completed. Root think_node
    doesn't need this because its sync_record_step is invoked AFTER analysis.

    No-op when tool_name == 'query_graph' (matches the inline bridge logic
    inside _write_step).
    """
    if not neo4j_uri or not neo4j_password:
        return
    if tool_name == "query_graph":
        return
    if not extracted_info:
        return
    _fire_and_forget(
        _write_bridges,
        neo4j_uri, neo4j_user, neo4j_password,
        step_id, extracted_info, user_id, project_id,
    )


def _write_bridges(uri, user, password, step_id, extracted_info, user_id, project_id):
    """Open a Neo4j session and delegate to the existing bridge resolver."""
    driver = _get_driver(uri, user, password)
    with driver.session() as session:
        _resolve_step_bridges(session, step_id, extracted_info or {}, user_id, project_id)


def _resolve_step_bridges(session, step_id, extracted_info, user_id, project_id):
    """Create bridge rels from ChainStep to recon nodes using extracted_info.

    Uses UNWIND for batch efficiency instead of per-item queries.
    """
    uid = user_id
    pid = project_id

    # --- STEP_TARGETED -> IP or Subdomain (based on primary_target) ---
    primary_target = extracted_info.get("primary_target") or ""
    if primary_target:
        if _looks_like_ip(primary_target):
            session.run(
                """
                MATCH (s:ChainStep {step_id: $step_id})
                OPTIONAL MATCH (ip:IP {address: $ip, user_id: $uid, project_id: $pid})
                FOREACH (_ IN CASE WHEN ip IS NOT NULL THEN [1] ELSE [] END |
                    MERGE (s)-[:STEP_TARGETED]->(ip))
                """,
                {"step_id": step_id, "ip": primary_target, "uid": uid, "pid": pid},
            )
        else:
            session.run(
                """
                MATCH (s:ChainStep {step_id: $step_id})
                OPTIONAL MATCH (sub:Subdomain {name: $hostname, user_id: $uid, project_id: $pid})
                FOREACH (_ IN CASE WHEN sub IS NOT NULL THEN [1] ELSE [] END |
                    MERGE (s)-[:STEP_TARGETED]->(sub))
                """,
                {"step_id": step_id, "hostname": primary_target, "uid": uid, "pid": pid},
            )

    # --- STEP_TARGETED -> Port (batched via UNWIND) ---
    ports = [p for p in (extracted_info.get("ports") or []) if p is not None]
    if ports:
        session.run(
            """
            UNWIND $ports AS port_num
            MATCH (s:ChainStep {step_id: $step_id})
            OPTIONAL MATCH (p:Port {number: port_num, user_id: $uid, project_id: $pid})
            FOREACH (_ IN CASE WHEN p IS NOT NULL THEN [1] ELSE [] END |
                MERGE (s)-[:STEP_TARGETED]->(p))
            """,
            {"step_id": step_id, "ports": ports, "uid": uid, "pid": pid},
        )

    # --- STEP_EXPLOITED -> CVE (batched via UNWIND) ---
    vulns = [v for v in (extracted_info.get("vulnerabilities") or []) if v]
    if vulns:
        session.run(
            """
            UNWIND $vulns AS cve_id
            MATCH (s:ChainStep {step_id: $step_id})
            OPTIONAL MATCH (c:CVE {id: cve_id, user_id: $uid, project_id: $pid})
            FOREACH (_ IN CASE WHEN c IS NOT NULL THEN [1] ELSE [] END |
                MERGE (s)-[:STEP_EXPLOITED]->(c))
            """,
            {"step_id": step_id, "vulns": vulns, "uid": uid, "pid": pid},
        )

    # --- STEP_IDENTIFIED -> Technology (batched via UNWIND, case-insensitive) ---
    technologies = [t for t in (extracted_info.get("technologies") or []) if t]
    if technologies:
        session.run(
            """
            UNWIND $techs AS tech_name
            MATCH (s:ChainStep {step_id: $step_id})
            OPTIONAL MATCH (t:Technology {user_id: $uid, project_id: $pid})
                WHERE toLower(t.name) = toLower(tech_name)
            WITH s, tech_name, head(collect(t)) AS t
            FOREACH (_ IN CASE WHEN t IS NOT NULL THEN [1] ELSE [] END |
                MERGE (s)-[:STEP_IDENTIFIED]->(t))
            """,
            {"step_id": step_id, "techs": technologies, "uid": uid, "pid": pid},
        )



# -------------------------------------------------------------------
# 3. ChainFinding
# -------------------------------------------------------------------

def fire_record_finding(
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    *,
    chain_id: str,
    step_id: str,
    user_id: str,
    project_id: str,
    finding_type: str = "custom",
    severity: str = "info",
    title: str = "",
    description: str = "",
    evidence: str = "",
    confidence: int = 80,
    phase: str = "",
    iteration: Optional[int] = None,
    related_cves: Optional[List[str]] = None,
    related_ips: Optional[List[str]] = None,
    metadata: Optional[dict] = None,
    agent_id: str = "root",
    source_agent: str = "root",
    fireteam_id: Optional[str] = None,
) -> None:
    if not neo4j_uri or not neo4j_password:
        return
    _fire_and_forget(
        _write_finding,
        neo4j_uri, neo4j_user, neo4j_password,
        finding_id=_uid(),
        chain_id=chain_id,
        step_id=step_id,
        user_id=user_id,
        project_id=project_id,
        finding_type=finding_type,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
        confidence=confidence,
        phase=phase,
        iteration=iteration,
        related_cves=related_cves or [],
        related_ips=related_ips or [],
        agent_id=agent_id,
        source_agent=source_agent,
        fireteam_id=fireteam_id,
    )


def _write_finding(
    uri, user, password,
    *,
    finding_id, chain_id, step_id, user_id, project_id,
    finding_type, severity, title, description, evidence,
    confidence, phase, iteration, related_cves, related_ips,
    agent_id="root", source_agent="root", fireteam_id=None,
):
    driver = _get_driver(uri, user, password)
    # MATCH step first so the finding is only created if the step exists
    # (prevents orphaned findings when fire_record_step hasn't completed yet)
    cypher = """
    MATCH (s:ChainStep {step_id: $step_id})
    CREATE (f:ChainFinding {
        finding_id:   $finding_id,
        chain_id:     $chain_id,
        user_id:      $user_id,
        project_id:   $project_id,
        finding_type: $finding_type,
        severity:     $severity,
        title:        $title,
        description:  $description,
        evidence:     $evidence,
        confidence:   $confidence,
        phase:        $phase,
        iteration:    $iteration,
        agent_id:     $agent_id,
        source_agent: $source_agent,
        fireteam_id:  $fireteam_id,
        created_at:   datetime()
    })
    MERGE (s)-[:PRODUCED]->(f)
    RETURN f.finding_id AS fid
    """
    params = {
        "finding_id": finding_id,
        "chain_id": chain_id,
        "step_id": step_id,
        "user_id": user_id,
        "project_id": project_id,
        "finding_type": finding_type or "custom",
        "severity": severity or "info",
        "title": title or "",
        "description": description or "",
        "evidence": evidence or "",
        "confidence": confidence if confidence is not None else 80,
        "phase": phase or "",
        "iteration": iteration,
        "agent_id": agent_id or "root",
        "source_agent": source_agent or "root",
        "fireteam_id": fireteam_id,
    }

    with driver.session() as session:
        result = session.run(cypher, params)
        if result.single() is None:
            logger.warning("ChainStep %s not found — skipping finding %s", step_id, title[:60])
            return
        _resolve_finding_bridges(
            session, finding_id, related_cves, related_ips, finding_type,
            user_id, project_id, evidence=evidence or "",
        )

    logger.debug("[%s/%s] ChainFinding created: %s (%s)", user_id, project_id, title[:60], finding_type)


_CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_URL_PATH_REGEX = re.compile(r"(?<![\w/])(/[A-Za-z0-9][A-Za-z0-9_\-./]{0,200})")
_PORT_REGEX = re.compile(r"(?:port\s*|:)(\d{2,5})(?:/(?:tcp|udp))?\b", re.IGNORECASE)


def _auto_extract_from_evidence(evidence: str) -> dict:
    """Pull CVE ids, URL paths, and port numbers out of free-form evidence text.

    LLM-structured fields (related_cves, related_ips) are often left empty
    because the extraction prompt doesn't emphasize them. This regex sweep is a
    best-effort fallback so bridges still land when the evidence text obviously
    names a CVE / endpoint / port.

    Duplicates against explicit input fields are de-duped by the caller.
    """
    text = evidence or ""
    if not text:
        return {"cves": [], "paths": [], "ports": []}

    cves = sorted({m.group(0).upper() for m in _CVE_REGEX.finditer(text)})

    # Only accept paths with a plausible application shape; reject asset noise.
    paths = []
    for m in _URL_PATH_REGEX.finditer(text):
        p = m.group(1).rstrip(").,:;\"'")
        if not p or len(p) < 2:
            continue
        # Skip obviously-static-asset paths that explode Endpoint matching.
        lower = p.lower()
        if any(lower.endswith(ext) for ext in (
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
            ".css", ".woff", ".woff2", ".ttf", ".map",
        )):
            continue
        if p not in paths:
            paths.append(p)
        if len(paths) >= 20:
            break

    ports = sorted({int(m.group(1)) for m in _PORT_REGEX.finditer(text)
                    if 1 <= int(m.group(1)) <= 65535})

    return {"cves": cves, "paths": paths, "ports": ports}


def _resolve_finding_bridges(
    session, finding_id, related_cves, related_ips, finding_type, user_id, project_id,
    *, evidence: str = "",
):
    """Create bridge rels from ChainFinding to recon nodes.

    Explicit `related_cves` / `related_ips` come from the LLM's structured
    extraction. Since the LLM often leaves those empty, we ALSO regex-scan
    the evidence text for CVE ids, URL paths, and port numbers, and bridge
    those to Endpoint / Port / Technology nodes when they exist in-scope.

    All MATCHes are scoped by (user_id, project_id) to respect tenant
    isolation. Uses UNWIND for batch efficiency; silently skips bridges to
    nodes that don't exist.
    """
    uid = user_id
    pid = project_id

    auto = _auto_extract_from_evidence(evidence)

    # FOUND_ON -> IP or Subdomain (pre-sort by type, then batch each)
    ip_addrs = []
    hostnames = []
    for addr in (related_ips or []):
        if not addr:
            continue
        if _looks_like_ip(addr):
            ip_addrs.append(addr)
        else:
            hostnames.append(addr)

    if ip_addrs:
        session.run(
            """
            UNWIND $addrs AS ip_addr
            MATCH (f:ChainFinding {finding_id: $fid})
            OPTIONAL MATCH (ip:IP {address: ip_addr, user_id: $uid, project_id: $pid})
            FOREACH (_ IN CASE WHEN ip IS NOT NULL THEN [1] ELSE [] END |
                MERGE (f)-[:FOUND_ON]->(ip))
            """,
            {"fid": finding_id, "addrs": ip_addrs, "uid": uid, "pid": pid},
        )

    if hostnames:
        session.run(
            """
            UNWIND $hosts AS hostname
            MATCH (f:ChainFinding {finding_id: $fid})
            OPTIONAL MATCH (sub:Subdomain {name: hostname, user_id: $uid, project_id: $pid})
            FOREACH (_ IN CASE WHEN sub IS NOT NULL THEN [1] ELSE [] END |
                MERGE (f)-[:FOUND_ON]->(sub))
            """,
            {"fid": finding_id, "hosts": hostnames, "uid": uid, "pid": pid},
        )

    # FINDING_RELATES_CVE -> CVE (batched via UNWIND). Merge explicit + auto.
    explicit_cves = [c for c in (related_cves or []) if c]
    cves = sorted({c.upper() for c in explicit_cves + auto["cves"]})
    if cves:
        session.run(
            """
            UNWIND $cves AS cve_id
            MATCH (f:ChainFinding {finding_id: $fid})
            OPTIONAL MATCH (c:CVE {user_id: $uid, project_id: $pid})
            WHERE toUpper(coalesce(c.id, c.cve_id, '')) = cve_id
            FOREACH (_ IN CASE WHEN c IS NOT NULL THEN [1] ELSE [] END |
                MERGE (f)-[:FINDING_RELATES_CVE]->(c))
            """,
            {"fid": finding_id, "cves": cves, "uid": uid, "pid": pid},
        )

    # FINDING_AFFECTS_ENDPOINT -> Endpoint (matched by path or full_url suffix)
    if auto["paths"]:
        session.run(
            """
            UNWIND $paths AS p
            MATCH (f:ChainFinding {finding_id: $fid})
            OPTIONAL MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
            WHERE e.path = p OR (e.full_url IS NOT NULL AND e.full_url ENDS WITH p)
            FOREACH (_ IN CASE WHEN e IS NOT NULL THEN [1] ELSE [] END |
                MERGE (f)-[:FINDING_AFFECTS_ENDPOINT]->(e))
            """,
            {"fid": finding_id, "paths": auto["paths"], "uid": uid, "pid": pid},
        )

    # FINDING_AFFECTS_PORT -> Port (number match within tenant).
    if auto["ports"]:
        session.run(
            """
            UNWIND $ports AS pn
            MATCH (f:ChainFinding {finding_id: $fid})
            OPTIONAL MATCH (p:Port {number: pn, user_id: $uid, project_id: $pid})
            FOREACH (_ IN CASE WHEN p IS NOT NULL THEN [1] ELSE [] END |
                MERGE (f)-[:FINDING_AFFECTS_PORT]->(p))
            """,
            {"fid": finding_id, "ports": auto["ports"], "uid": uid, "pid": pid},
        )

    # FINDING_AFFECTS_TECH -> Technology (name appears as whole word in evidence).
    # Uses a server-side scan of the in-scope Technology set; cheap because
    # there are usually <20 Technology nodes per project and evidence is short.
    if (evidence or "").strip():
        session.run(
            """
            MATCH (f:ChainFinding {finding_id: $fid})
            MATCH (t:Technology {user_id: $uid, project_id: $pid})
            WHERE t.name IS NOT NULL
              AND size(t.name) >= 3
              AND toLower($evidence) CONTAINS toLower(t.name)
            MERGE (f)-[:FINDING_AFFECTS_TECH]->(t)
            """,
            {"fid": finding_id, "evidence": evidence[:4000], "uid": uid, "pid": pid},
        )


# -------------------------------------------------------------------
# 4. ChainFailure
# -------------------------------------------------------------------

def fire_record_failure(
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    *,
    chain_id: str,
    step_id: str,
    user_id: str,
    project_id: str,
    failure_type: str = "tool_error",
    tool_name: str = "",
    error_category: str = "",
    error_message: str = "",
    lesson_learned: str = "",
    retry_possible: bool = True,
    phase: str = "",
    iteration: Optional[int] = None,
) -> None:
    if not neo4j_uri or not neo4j_password:
        return
    _fire_and_forget(
        _write_failure,
        neo4j_uri, neo4j_user, neo4j_password,
        failure_id=_uid(),
        chain_id=chain_id,
        step_id=step_id,
        user_id=user_id,
        project_id=project_id,
        failure_type=failure_type,
        tool_name=tool_name,
        error_category=error_category,
        error_message=error_message,
        lesson_learned=lesson_learned,
        retry_possible=retry_possible,
        phase=phase,
        iteration=iteration,
    )


def _write_failure(
    uri, user, password,
    *,
    failure_id, chain_id, step_id, user_id, project_id,
    failure_type, tool_name, error_category, error_message,
    lesson_learned, retry_possible, phase, iteration,
):
    driver = _get_driver(uri, user, password)
    cypher = """
    CREATE (fl:ChainFailure {
        failure_id:     $failure_id,
        chain_id:       $chain_id,
        user_id:        $user_id,
        project_id:     $project_id,
        failure_type:   $failure_type,
        tool_name:      $tool_name,
        error_category: $error_category,
        error_message:  $error_message,
        iteration:      $iteration,
        lesson_learned: $lesson_learned,
        retry_possible: $retry_possible,
        phase:          $phase,
        created_at:     datetime()
    })
    WITH fl
    MATCH (s:ChainStep {step_id: $step_id})
    MERGE (s)-[:FAILED_WITH]->(fl)
    """
    with driver.session() as session:
        session.run(cypher, {
            "failure_id": failure_id,
            "chain_id": chain_id,
            "step_id": step_id,
            "user_id": user_id,
            "project_id": project_id,
            "failure_type": failure_type or "tool_error",
            "tool_name": tool_name or "",
            "error_category": error_category or "",
            "error_message": error_message or "",
            "lesson_learned": lesson_learned or "",
            "retry_possible": retry_possible,
            "phase": phase or "",
            "iteration": iteration,
        })
    logger.debug("[%s/%s] ChainFailure created: %s (%s)", user_id, project_id, tool_name, failure_type)


# -------------------------------------------------------------------
# 5. ChainDecision
# -------------------------------------------------------------------

def fire_record_decision(
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    *,
    chain_id: str,
    step_id: Optional[str],
    user_id: str,
    project_id: str,
    decision_type: str = "phase_transition",
    from_state: str = "",
    to_state: str = "",
    reason: str = "",
    made_by: str = "user",
    approved: bool = True,
    iteration: Optional[int] = None,
) -> None:
    if not neo4j_uri or not neo4j_password:
        return
    _fire_and_forget(
        _write_decision,
        neo4j_uri, neo4j_user, neo4j_password,
        decision_id=_uid(),
        chain_id=chain_id,
        step_id=step_id,
        user_id=user_id,
        project_id=project_id,
        decision_type=decision_type,
        from_state=from_state,
        to_state=to_state,
        reason=reason,
        made_by=made_by,
        approved=approved,
        iteration=iteration,
    )


def _write_decision(
    uri, user, password,
    *,
    decision_id, chain_id, step_id, user_id, project_id,
    decision_type, from_state, to_state, reason, made_by, approved,
    iteration,
):
    driver = _get_driver(uri, user, password)
    cypher = """
    CREATE (d:ChainDecision {
        decision_id:   $decision_id,
        chain_id:      $chain_id,
        user_id:       $user_id,
        project_id:    $project_id,
        decision_type: $decision_type,
        from_state:    $from_state,
        to_state:      $to_state,
        reason:        $reason,
        made_by:       $made_by,
        approved:      $approved,
        iteration:     $iteration,
        created_at:    datetime()
    })
    """
    params = {
        "decision_id": decision_id,
        "chain_id": chain_id,
        "user_id": user_id,
        "project_id": project_id,
        "decision_type": decision_type or "phase_transition",
        "from_state": from_state or "",
        "to_state": to_state or "",
        "reason": reason or "",
        "made_by": made_by or "user",
        "approved": approved,
        "iteration": iteration,
    }

    with driver.session() as session:
        session.run(cypher, params)
        # Link to the step that triggered this decision
        if step_id:
            session.run(
                """
                MATCH (s:ChainStep {step_id: $step_id})
                MATCH (d:ChainDecision {decision_id: $decision_id})
                MERGE (s)-[:LED_TO]->(d)
                """,
                {"step_id": step_id, "decision_id": decision_id},
            )
    logger.debug("[%s/%s] ChainDecision created: %s -> %s", user_id, project_id, from_state, to_state)


# -------------------------------------------------------------------
# 6. Exploit success (absorbs exploit_writer logic)
# -------------------------------------------------------------------

def fire_record_exploit_success(
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    *,
    chain_id: str,
    step_id: str,
    user_id: str,
    project_id: str,
    attack_type: str = "cve_exploit",
    target_ip: Optional[str] = None,
    target_port: Optional[int] = None,
    cve_ids: Optional[List[str]] = None,
    metasploit_module: Optional[str] = None,
    payload: Optional[str] = None,
    session_id: Optional[int] = None,
    username: Optional[str] = None,
    password_found: Optional[str] = None,
    evidence: str = "",
    execution_trace: Optional[List[Dict[str, Any]]] = None,
    iteration: Optional[int] = None,
) -> None:
    if not neo4j_uri or not neo4j_password:
        return
    _fire_and_forget(
        _write_exploit_success,
        neo4j_uri, neo4j_user, neo4j_password,
        chain_id=chain_id,
        step_id=step_id,
        user_id=user_id,
        project_id=project_id,
        attack_type=attack_type,
        target_ip=target_ip,
        target_port=target_port,
        cve_ids=cve_ids,
        metasploit_module=metasploit_module,
        payload=payload,
        session_id=session_id,
        username=username,
        password_found=password_found,
        evidence=evidence,
        execution_trace=execution_trace,
        iteration=iteration,
    )


def _write_exploit_success(
    uri, user, password,
    *,
    chain_id, step_id, user_id, project_id,
    attack_type, target_ip, target_port, cve_ids,
    metasploit_module, payload, session_id, username,
    password_found, evidence, execution_trace, iteration,
):
    driver = _get_driver(uri, user, password)

    # Extract MSF info from trace (same logic as old exploit_writer)
    msf_info = _extract_metasploit_info(execution_trace or [])
    effective_module = metasploit_module or msf_info.get("metasploit_module")
    effective_payload = payload or msf_info.get("payload")
    commands_used = msf_info.get("commands_used", [])

    # Build report
    report = _build_exploit_report(
        attack_type, target_ip, target_port, cve_ids,
        username, session_id, evidence, msf_info,
    )

    finding_id = _uid()

    # Build properties dict for the finding
    props = {
        "finding_id": finding_id,
        "chain_id": chain_id,
        "user_id": user_id,
        "project_id": project_id,
        "finding_type": "exploit_success",
        "severity": "critical",
        "iteration": iteration,
        "title": f"Exploit success: {attack_type} on {target_ip or 'unknown'}",
        "description": report,
        "evidence": evidence or "",
        "confidence": 95,
        "phase": "exploitation",
        "attack_type": attack_type or "cve_exploit",
        "target_ip": target_ip or "",
        "report": report,
    }
    if target_port is not None:
        props["target_port"] = target_port
    if cve_ids:
        props["cve_ids"] = cve_ids
    if effective_module:
        props["metasploit_module"] = effective_module
    if effective_payload:
        props["payload"] = effective_payload
    if commands_used:
        props["commands_used"] = commands_used
    if session_id is not None:
        props["session_id"] = session_id
    if username:
        props["username"] = username
    if password_found:
        props["password"] = password_found

    with driver.session() as session:
        # Guard: skip if an exploit_success finding already exists for this step
        dup_check = session.run(
            """
            MATCH (s:ChainStep {step_id: $step_id})-[:PRODUCED]->(f:ChainFinding {finding_type: 'exploit_success'})
            RETURN f.finding_id AS fid LIMIT 1
            """,
            {"step_id": step_id},
        )
        if dup_check.single() is not None:
            logger.debug("Exploit success finding already exists for step %s — skipping", step_id)
            return

        # Create ChainFinding(exploit_success) node — only if step exists
        cypher = """
        MATCH (s:ChainStep {step_id: $step_id})
        CREATE (f:ChainFinding $props)
        SET f.created_at = datetime()
        MERGE (s)-[:PRODUCED]->(f)
        RETURN f.finding_id AS fid
        """
        result = session.run(cypher, {"props": props, "step_id": step_id})
        if result.single() is None:
            logger.warning("ChainStep %s not found — skipping exploit success finding", step_id)
            return

        # Bridge: FOUND_ON -> IP or Subdomain
        if target_ip:
            if _looks_like_ip(target_ip):
                session.run(
                    """
                    MATCH (f:ChainFinding {finding_id: $fid})
                    OPTIONAL MATCH (ip:IP {address: $ip, user_id: $uid, project_id: $pid})
                    FOREACH (_ IN CASE WHEN ip IS NOT NULL THEN [1] ELSE [] END |
                        MERGE (f)-[:FOUND_ON]->(ip))
                    """,
                    {"fid": finding_id, "ip": target_ip, "uid": user_id, "pid": project_id},
                )
            else:
                session.run(
                    """
                    MATCH (f:ChainFinding {finding_id: $fid})
                    OPTIONAL MATCH (sub:Subdomain {name: $hostname, user_id: $uid, project_id: $pid})
                    FOREACH (_ IN CASE WHEN sub IS NOT NULL THEN [1] ELSE [] END |
                        MERGE (f)-[:FOUND_ON]->(sub))
                    """,
                    {"fid": finding_id, "hostname": target_ip, "uid": user_id, "pid": project_id},
                )

        # Bridge: FINDING_RELATES_CVE -> CVE (batched via UNWIND)
        cve_list = [c for c in (cve_ids or []) if c]
        if cve_list:
            session.run(
                """
                UNWIND $cves AS cve_id
                MATCH (f:ChainFinding {finding_id: $fid})
                OPTIONAL MATCH (c:CVE {id: cve_id, user_id: $uid, project_id: $pid})
                FOREACH (_ IN CASE WHEN c IS NOT NULL THEN [1] ELSE [] END |
                    MERGE (f)-[:FINDING_RELATES_CVE]->(c))
                """,
                {"fid": finding_id, "cves": cve_list, "uid": user_id, "pid": project_id},
            )

        # Bridge: STEP_TARGETED -> IP or Subdomain (on the step node)
        if target_ip:
            if _looks_like_ip(target_ip):
                session.run(
                    """
                    MATCH (s:ChainStep {step_id: $step_id})
                    OPTIONAL MATCH (ip:IP {address: $ip, user_id: $uid, project_id: $pid})
                    FOREACH (_ IN CASE WHEN ip IS NOT NULL THEN [1] ELSE [] END |
                        MERGE (s)-[:STEP_TARGETED]->(ip))
                    """,
                    {"step_id": step_id, "ip": target_ip, "uid": user_id, "pid": project_id},
                )
            else:
                session.run(
                    """
                    MATCH (s:ChainStep {step_id: $step_id})
                    OPTIONAL MATCH (sub:Subdomain {name: $hostname, user_id: $uid, project_id: $pid})
                    FOREACH (_ IN CASE WHEN sub IS NOT NULL THEN [1] ELSE [] END |
                        MERGE (s)-[:STEP_TARGETED]->(sub))
                    """,
                    {"step_id": step_id, "hostname": target_ip, "uid": user_id, "pid": project_id},
                )

        # Bridge: STEP_EXPLOITED -> CVE (on the step node, batched via UNWIND)
        if cve_list:
            session.run(
                """
                UNWIND $cves AS cve_id
                MATCH (s:ChainStep {step_id: $step_id})
                OPTIONAL MATCH (c:CVE {id: cve_id, user_id: $uid, project_id: $pid})
                FOREACH (_ IN CASE WHEN c IS NOT NULL THEN [1] ELSE [] END |
                    MERGE (s)-[:STEP_EXPLOITED]->(c))
                """,
                {"step_id": step_id, "cves": cve_list, "uid": user_id, "pid": project_id},
            )

    logger.info(
        "[%s/%s] Exploit success recorded as ChainFinding: %s (%s, target=%s)",
        user_id, project_id, finding_id, attack_type, target_ip,
    )


# -------------------------------------------------------------------
# 7. Update chain status (completion)
# -------------------------------------------------------------------

def fire_update_chain_status(
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    *,
    chain_id: str,
    status: str = "completed",
    final_outcome: str = "",
    total_steps: int = 0,
    successful_steps: int = 0,
    failed_steps: int = 0,
    phases_reached: Optional[List[str]] = None,
) -> None:
    if not neo4j_uri or not neo4j_password:
        return
    _fire_and_forget(
        _write_chain_status,
        neo4j_uri, neo4j_user, neo4j_password,
        chain_id=chain_id,
        status=status,
        final_outcome=final_outcome,
        total_steps=total_steps,
        successful_steps=successful_steps,
        failed_steps=failed_steps,
        phases_reached=phases_reached,
    )


def _write_chain_status(
    uri, user, password,
    *,
    chain_id, status, final_outcome,
    total_steps, successful_steps, failed_steps, phases_reached,
):
    driver = _get_driver(uri, user, password)
    cypher = """
    MATCH (ac:AttackChain {chain_id: $chain_id})
    SET ac.status           = $status,
        ac.final_outcome    = $final_outcome,
        ac.total_steps      = $total_steps,
        ac.successful_steps = $successful_steps,
        ac.failed_steps     = $failed_steps,
        ac.phases_reached   = $phases_reached,
        ac.updated_at       = datetime()
    """
    with driver.session() as session:
        session.run(cypher, {
            "chain_id": chain_id,
            "status": status or "completed",
            "final_outcome": final_outcome or "",
            "total_steps": total_steps,
            "successful_steps": successful_steps,
            "failed_steps": failed_steps,
            "phases_reached": phases_reached or [],
        })
    logger.info("AttackChain %s status -> %s (steps=%d)", chain_id, status, total_steps)


# -------------------------------------------------------------------
# 8. Query prior chains (SYNCHRONOUS — needs result)
# -------------------------------------------------------------------

def query_prior_chains(
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    user_id: str,
    project_id: str,
    current_chain_id: str,
    limit: int = 5,
) -> List[Dict[str, Any]]:
    """Query prior completed attack chains for cross-session context.

    Returns a list of dicts with chain summary info.
    This is SYNCHRONOUS because we need the result before proceeding.
    """
    if not neo4j_uri or not neo4j_password:
        return []

    try:
        driver = _get_driver(neo4j_uri, neo4j_user, neo4j_password)
        cypher = """
        MATCH (ac:AttackChain {user_id: $user_id, project_id: $project_id})
        WHERE ac.chain_id <> $current_chain_id
          AND ac.status IN ['completed', 'aborted']
        OPTIONAL MATCH (ac)-[:HAS_STEP]->(:ChainStep)-[:NEXT_STEP*0..]->(s:ChainStep)-[:PRODUCED]->(f:ChainFinding)
        WHERE f.severity IN ['critical', 'high']
        OPTIONAL MATCH (ac)-[:HAS_STEP]->(:ChainStep)-[:NEXT_STEP*0..]->(s2:ChainStep)-[:FAILED_WITH]->(fl:ChainFailure)
        WITH ac,
             collect(DISTINCT {type: f.finding_type, title: f.title, severity: f.severity}) AS findings,
             collect(DISTINCT {type: fl.failure_type, lesson: fl.lesson_learned}) AS failures
        RETURN ac.chain_id AS chain_id,
               ac.title AS title,
               ac.objective AS objective,
               ac.status AS status,
               ac.attack_path_type AS attack_path_type,
               ac.total_steps AS total_steps,
               ac.successful_steps AS successful_steps,
               ac.failed_steps AS failed_steps,
               ac.phases_reached AS phases_reached,
               ac.final_outcome AS final_outcome,
               findings,
               failures,
               ac.created_at AS created_at
        ORDER BY ac.created_at DESC
        LIMIT $limit
        """
        with driver.session() as session:
            result = session.run(cypher, {
                "user_id": user_id,
                "project_id": project_id,
                "current_chain_id": current_chain_id,
                "limit": limit,
            })
            return [dict(record) for record in result]
    except Exception as exc:
        logger.error("Failed to query prior chains: %s", exc)
        return []

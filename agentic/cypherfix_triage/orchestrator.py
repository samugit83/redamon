"""Hybrid triage orchestrator: static Cypher collection + ReAct LLM analysis."""

import json
import logging
import os
import re
from typing import Optional

import httpx

from .state import TriageState, TriageFinding, RemediationDraft
from .tools import TriageNeo4jToolManager, TriageWebSearchManager, TRIAGE_TOOLS
from .prompts.cypher_queries import TRIAGE_QUERIES
from .prompts.system import TRIAGE_SYSTEM_PROMPT
from .project_settings import load_cypherfix_settings

logger = logging.getLogger(__name__)

WEBAPP_API_URL = os.environ.get("WEBAPP_API_URL", "http://webapp:3000")
INTERNAL_HEADERS = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}


class TriageOrchestrator:
    """
    Hybrid triage orchestrator:
    Phase 1: Static collection (9 hardcoded Cypher queries, no LLM)
    Phase 2: ReAct analysis (LLM correlates, deduplicates, prioritizes)
    """

    def __init__(self, user_id: str, project_id: str, callback):
        self.user_id = user_id
        self.project_id = project_id
        self.callback = callback
        self.neo4j = TriageNeo4jToolManager(user_id, project_id)
        self.web_search = None  # Initialized after settings load
        self.llm_client = None

    async def run(self, state: TriageState) -> TriageState:
        """Main entry point: collect -> analyze -> save."""
        # Load settings
        settings = await load_cypherfix_settings(self.project_id)
        state["settings"] = settings

        # Initialize web search with Tavily key from user settings
        user_settings = settings.get("user_settings", {})
        tavily_key = user_settings.get("tavilyApiKey", "")
        self.web_search = TriageWebSearchManager(tavily_api_key=tavily_key)

        # Initialize LLM
        self.llm_client = await self._init_llm(settings)

        # Phase 1: Static Collection
        await self.callback.on_phase("collecting_vulnerabilities", "Starting data collection...", 0)
        raw_data = await self._collect_all(state)
        state["raw_data"] = raw_data

        # Check if there's any data
        total_records = sum(len(v) for v in raw_data.values())
        if total_records == 0:
            await self.callback.on_complete(0, {}, {}, "No security data found in the graph.")
            state["status"] = "complete"
            return state

        # Fetch existing non-pending remediations to avoid duplicates on re-triage
        existing_remediations = await self._fetch_existing_remediations()

        # Phase 2: ReAct Analysis
        await self.callback.on_phase("correlating", "Analyzing collected data...", 70)
        analysis = await self._analyze(state, raw_data, existing_remediations)
        state["analysis_result"] = analysis

        # Phase 3: Save to database
        await self.callback.on_phase("saving", "Saving remediations...", 95)
        await self._save_remediations(analysis)

        # Complete
        await self.callback.on_complete(
            total=len(analysis.findings),
            by_severity=analysis.by_severity,
            by_type=analysis.by_type,
            summary=analysis.summary,
        )
        state["status"] = "complete"
        return state

    async def _collect_all(self, state: TriageState) -> dict:
        """Phase 1: Run all 9 static Cypher queries."""
        await self.neo4j.connect()
        raw_data = {}

        for i, query_def in enumerate(TRIAGE_QUERIES):
            phase = query_def["phase"]
            description = query_def["description"]
            progress = int((i / len(TRIAGE_QUERIES)) * 65) + 5  # 5-70%

            await self.callback.on_phase(phase, f"Collecting: {description}", progress)
            state["current_phase"] = phase

            try:
                records = await self.neo4j.run_static_query(query_def["query"])
                raw_data[query_def["name"]] = records
                logger.info(f"Triage query '{query_def['name']}': {len(records)} records")
            except Exception as e:
                logger.error(f"Triage query '{query_def['name']}' failed: {e}")
                raw_data[query_def["name"]] = []

        return raw_data

    async def _analyze(self, state: TriageState, raw_data: dict, existing_remediations: list) -> RemediationDraft:
        """Phase 2: ReAct analysis using LLM."""
        data_text = self._format_raw_data(raw_data)

        existing_text = ""
        if existing_remediations:
            existing_text = (
                "\n\n---\n\n## Existing Remediations (already tracked)\n\n"
                "The following remediations already exist in the database with non-pending status "
                "(in_progress, fixed, dismissed). Do NOT create new entries that duplicate these. "
                "Only create remediations for NEW findings not covered below.\n\n"
                f"```json\n{json.dumps(existing_remediations, default=str)[:20000]}\n```"
            )

        messages = [
            {
                "role": "user",
                "content": (
                    f"Here is the raw security reconnaissance data collected from the graph database "
                    f"for project {self.project_id}:\n\n{data_text}"
                    f"{existing_text}\n\n"
                    "Analyze this data following the instructions in your system prompt. "
                    "Correlate, deduplicate, prioritize, and generate remediation entries. "
                    "Output the final remediations as a JSON array wrapped in ```json``` code fence."
                ),
            }
        ]

        max_iterations = 10
        iteration = 0

        while iteration < max_iterations:
            iteration += 1

            try:
                response = await self._call_llm(
                    system=TRIAGE_SYSTEM_PROMPT,
                    messages=messages,
                    tools=TRIAGE_TOOLS,
                )
            except Exception as e:
                logger.error(f"LLM call failed: {e}")
                await self.callback.on_error(f"LLM error: {e}", recoverable=False)
                return RemediationDraft()

            # Append assistant message (include tool_uses so _call_llm can reconstruct properly)
            messages.append({
                "role": "assistant",
                "content": response["content"],
                "tool_uses": response.get("tool_uses", []),
            })

            # Check if done (no tool calls)
            if response.get("stop_reason") == "end_turn" or not response.get("tool_uses"):
                return self._parse_findings(response["content"])

            # Execute tool calls
            tool_results = []
            for tool_use in response.get("tool_uses", []):
                tool_name = tool_use["name"]
                tool_input = tool_use["input"]

                await self.callback.on_tool_start(tool_name, tool_input)

                try:
                    if tool_name == "query_graph":
                        result = await self.neo4j.run_query(tool_input["cypher"])
                        result_str = json.dumps(result, default=str, indent=2)
                    elif tool_name == "web_search":
                        result_str = await self.web_search.search(tool_input["query"])
                    else:
                        result_str = f"Unknown tool: {tool_name}"

                    await self.callback.on_tool_complete(tool_name, True, result_str[:500])
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_use["id"],
                        "content": result_str[:20000],
                    })
                except Exception as e:
                    error_msg = f"Error: {e}"
                    await self.callback.on_tool_complete(tool_name, False, error_msg)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_use["id"],
                        "content": error_msg,
                        "is_error": True,
                    })

            messages.append({"role": "user", "content": tool_results})

        return RemediationDraft()

    async def _save_remediations(self, analysis: RemediationDraft):
        """Save remediations to the webapp API."""
        if not analysis.findings:
            return

        remediations = []
        for f in analysis.findings:
            rem = f.model_dump()
            remediations.append({
                "title": rem["title"],
                "description": rem["description"],
                "severity": rem["severity"],
                "priority": rem["priority"],
                "category": rem["category"],
                "remediationType": rem["remediation_type"],
                "affectedAssets": rem["affected_assets"],
                "cvssScore": rem["cvss_score"],
                "cveIds": rem["cve_ids"],
                "cweIds": rem["cwe_ids"],
                "capecIds": rem["capec_ids"],
                "evidence": rem["evidence"],
                "attackChainPath": rem["attack_chain_path"],
                "exploitAvailable": rem["exploit_available"],
                "cisaKev": rem["cisa_kev"],
                "solution": rem["solution"],
                "fixComplexity": rem["fix_complexity"],
                "estimatedFiles": rem["estimated_files"],
                "targetRepo": rem["target_repo"],
                "targetBranch": rem["target_branch"],
            })

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    f"{WEBAPP_API_URL}/api/remediations/batch",
                    json={"projectId": self.project_id, "remediations": remediations},
                    headers=INTERNAL_HEADERS,
                )
                resp.raise_for_status()
                logger.info(f"Saved {len(remediations)} remediations")
        except Exception as e:
            logger.error(f"Failed to save remediations: {e}")
            await self.callback.on_error(f"Failed to save: {e}", recoverable=False)

    async def _fetch_existing_remediations(self) -> list:
        """Fetch existing non-pending remediations to pass to LLM for dedup."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"{WEBAPP_API_URL}/api/remediations",
                    params={"projectId": self.project_id},
                    headers=INTERNAL_HEADERS,
                )
                resp.raise_for_status()
                all_rems = resp.json()
                # Keep only non-pending (in_progress, fixed, dismissed) — compact summary for LLM
                existing = []
                for r in all_rems:
                    if r.get("status") != "pending":
                        existing.append({
                            "title": r.get("title"),
                            "status": r.get("status"),
                            "severity": r.get("severity"),
                            "category": r.get("category"),
                            "cveIds": r.get("cveIds", []),
                        })
                logger.info(f"Fetched {len(existing)} existing non-pending remediations")
                return existing
        except Exception as e:
            logger.warning(f"Failed to fetch existing remediations: {e}")
            return []

    def _format_raw_data(self, raw_data: dict) -> str:
        """Format raw data for LLM consumption."""
        sections = []
        for name, records in raw_data.items():
            if records:
                sections.append(
                    f"## {name.replace('_', ' ').title()} ({len(records)} records)\n\n"
                    f"```json\n{json.dumps(records, default=str, indent=2)[:20000]}\n```"
                )
            else:
                sections.append(f"## {name.replace('_', ' ').title()}\n\nNo data found.")
        return "\n\n".join(sections)

    def _parse_findings(self, content) -> RemediationDraft:
        """Parse LLM output to extract remediation findings."""
        text = ""
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    text += block["text"]
                elif isinstance(block, str):
                    text += block
        else:
            text = str(content)

        # Extract JSON from code fence
        json_match = re.search(r'```json\s*([\s\S]*?)```', text)
        if not json_match:
            json_match = re.search(r'(\[[\s\S]*\])', text)

        if not json_match:
            logger.warning("No JSON found in LLM response")
            return RemediationDraft(summary="Analysis complete but no structured output found.")

        try:
            raw_json = json_match.group(1).strip()
            try:
                data = json.loads(raw_json)
            except json.JSONDecodeError as first_err:
                logger.warning(f"Initial JSON parse failed: {first_err}")
                logger.debug(f"Raw JSON (first 500): {raw_json[:500]}")
                logger.debug(f"Raw JSON (last 500): {raw_json[-500:]}")
                # Fallback: extract individual JSON objects via regex
                obj_pattern = re.compile(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', re.DOTALL)
                objects = obj_pattern.findall(raw_json)
                data = []
                for obj_str in objects:
                    try:
                        obj = json.loads(obj_str)
                        # Must have at least a title to be a valid finding
                        if isinstance(obj, dict) and "title" in obj:
                            data.append(obj)
                    except json.JSONDecodeError:
                        continue
                if data:
                    logger.warning(f"Recovered {len(data)} findings from malformed JSON")
                else:
                    raise first_err
            if not isinstance(data, list):
                data = [data]

            findings = []
            by_severity = {}
            by_type = {}

            for item in data:
                finding = TriageFinding(
                    title=item.get("title", "Unnamed Finding"),
                    description=item.get("description", ""),
                    severity=item.get("severity", "medium"),
                    priority=item.get("priority", 0),
                    category=item.get("category", "vulnerability"),
                    remediation_type=item.get("remediation_type", "code_fix"),
                    affected_assets=item.get("affected_assets", []),
                    cvss_score=item.get("cvss_score"),
                    cve_ids=item.get("cve_ids", []),
                    cwe_ids=item.get("cwe_ids", []),
                    capec_ids=item.get("capec_ids", []),
                    evidence=item.get("evidence", ""),
                    attack_chain_path=item.get("attack_chain_path", ""),
                    exploit_available=item.get("exploit_available", False),
                    cisa_kev=item.get("cisa_kev", False),
                    solution=item.get("solution", ""),
                    fix_complexity=item.get("fix_complexity", "medium"),
                    estimated_files=item.get("estimated_files", 0),
                    target_repo=item.get("target_repo", ""),
                    target_branch=item.get("target_branch", "main"),
                )
                findings.append(finding)

                sev = finding.severity
                by_severity[sev] = by_severity.get(sev, 0) + 1
                rtype = finding.remediation_type
                by_type[rtype] = by_type.get(rtype, 0) + 1

            return RemediationDraft(
                findings=findings,
                summary=f"Found {len(findings)} remediations across {len(by_severity)} severity levels.",
                by_severity=by_severity,
                by_type=by_type,
            )
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM JSON: {e}")
            return RemediationDraft(summary=f"JSON parse error: {e}")

    async def _init_llm(self, settings: dict):
        """Initialize LLM client using centralized setup_llm."""
        from orchestrator_helpers.llm_setup import setup_llm, _resolve_provider_key

        model = settings.get("llm_model", "")
        logger.info(f"Setting up triage LLM: {model}")

        user_providers = settings.get("user_llm_providers", [])
        custom_config = settings.get("custom_llm_config")

        openai_p = _resolve_provider_key(user_providers, "openai")
        anthropic_p = _resolve_provider_key(user_providers, "anthropic")
        openrouter_p = _resolve_provider_key(user_providers, "openrouter")
        bedrock_p = _resolve_provider_key(user_providers, "bedrock")

        return setup_llm(
            model,
            openai_api_key=(openai_p or {}).get("apiKey"),
            anthropic_api_key=(anthropic_p or {}).get("apiKey"),
            openrouter_api_key=(openrouter_p or {}).get("apiKey"),
            aws_access_key_id=(bedrock_p or {}).get("awsAccessKeyId"),
            aws_secret_access_key=(bedrock_p or {}).get("awsSecretKey"),
            aws_region=(bedrock_p or {}).get("awsRegion") or "us-east-1",
            custom_llm_config=custom_config,
        )

    async def _call_llm(self, system: str, messages: list, tools: list = None) -> dict:
        """Call the LLM and return structured response."""
        from langchain_core.messages import SystemMessage, HumanMessage, AIMessage, ToolMessage

        lc_messages = [SystemMessage(content=system)]

        for msg in messages:
            role = msg["role"]
            content = msg["content"]
            if role == "user":
                if isinstance(content, list):
                    # Check if all items are tool_results — use ToolMessage for each
                    all_tool_results = all(
                        isinstance(item, dict) and item.get("type") == "tool_result"
                        for item in content
                    )
                    if all_tool_results:
                        for item in content:
                            tool_content = item.get("content", "")
                            if item.get("is_error"):
                                tool_content = f"[ERROR] {tool_content}"
                            lc_messages.append(ToolMessage(
                                content=tool_content,
                                tool_call_id=item.get("tool_use_id", ""),
                            ))
                    else:
                        parts = []
                        for item in content:
                            if isinstance(item, dict) and item.get("type") == "tool_result":
                                prefix = "[ERROR] " if item.get("is_error") else ""
                                parts.append(
                                    f"Tool result ({item.get('tool_use_id', '')}):\n"
                                    f"{prefix}{item.get('content', '')}"
                                )
                            else:
                                parts.append(str(item))
                        lc_messages.append(HumanMessage(content="\n\n".join(parts)))
                else:
                    lc_messages.append(HumanMessage(content=content))
            elif role == "assistant":
                # Extract text content
                if isinstance(content, list):
                    text_parts = [
                        b["text"] for b in content
                        if isinstance(b, dict) and b.get("type") == "text"
                    ]
                    ai_content = "\n".join(text_parts) if text_parts else ""
                else:
                    ai_content = content or ""

                # Reconstruct tool_calls for LangChain if the assistant used tools
                tool_uses = msg.get("tool_uses", [])
                if tool_uses:
                    lc_tool_calls = [
                        {
                            "id": tu["id"],
                            "name": tu["name"],
                            "args": tu["input"],
                        }
                        for tu in tool_uses
                    ]
                    lc_messages.append(AIMessage(
                        content=ai_content,
                        tool_calls=lc_tool_calls,
                    ))
                else:
                    lc_messages.append(AIMessage(content=ai_content))

        # Bind tools if provided
        llm = self.llm_client
        if tools:
            llm = llm.bind_tools([
                {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["input_schema"],
                }
                for t in tools
            ])

        response = await llm.ainvoke(lc_messages)

        result = {
            "content": (
                response.content
                if isinstance(response.content, list)
                else [{"type": "text", "text": response.content}]
            ),
            "stop_reason": "end_turn",
            "tool_uses": [],
        }

        if hasattr(response, "tool_calls") and response.tool_calls:
            result["stop_reason"] = "tool_use"
            for tc in response.tool_calls:
                result["tool_uses"].append({
                    "id": tc.get("id", ""),
                    "name": tc["name"],
                    "input": tc["args"],
                })

        return result

    async def cleanup(self):
        """Clean up resources."""
        await self.neo4j.close()

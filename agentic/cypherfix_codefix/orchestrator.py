"""Pure ReAct loop orchestrator — Claude Code pattern."""

import asyncio
import json
import logging
import os
from typing import Optional

import httpx

from .state import CodeFixState, CodeFixSettings
from .tools import CODEFIX_TOOLS
from .tools.github_repo import GitHubRepoManager
from .tools.glob_tool import github_glob
from .tools.grep_tool import github_grep
from .tools.read_tool import github_read
from .tools.edit_tool import github_edit
from .tools.write_tool import github_write
from .tools.bash_tool import github_bash
from .tools.list_dir_tool import github_list_dir
from .tools.symbols_tool import github_symbols
from .tools.find_definition_tool import github_find_definition
from .tools.find_references_tool import github_find_references
from .tools.repo_map_tool import github_repo_map
from .prompts.system import build_codefix_system_prompt
from .project_settings import load_cypherfix_settings

logger = logging.getLogger(__name__)

WEBAPP_API_URL = os.environ.get("WEBAPP_API_URL", "http://webapp:3000")
INTERNAL_HEADERS = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}

TOOL_HANDLERS = {
    "github_glob": github_glob,
    "github_grep": github_grep,
    "github_read": github_read,
    "github_edit": github_edit,
    "github_write": github_write,
    "github_bash": github_bash,
    "github_list_dir": github_list_dir,
    "github_symbols": github_symbols,
    "github_find_definition": github_find_definition,
    "github_find_references": github_find_references,
    "github_repo_map": github_repo_map,
}

SEQUENTIAL_TOOLS = {"github_edit", "github_write", "github_bash"}


class CodeFixOrchestrator:
    """Pure ReAct loop — the LLM is the sole controller."""

    def __init__(self, state: CodeFixState, callback):
        self.state = state
        self.callback = callback
        self.repo_manager: Optional[GitHubRepoManager] = None
        self.llm_client = None
        self.approval_future: Optional[asyncio.Future] = None
        self.guidance_messages: list[str] = []
        self.max_output_chars = 20000
        self.context_compact_threshold = 0.80
        self.last_llm_text: str = ""

    async def run(self, remediation_id: str):
        """Main entry point."""
        SEP = "=" * 80
        logger.info(f"\n{SEP}\n  CODEFIX SESSION START — {remediation_id}\n{SEP}")

        # Load settings
        settings_dict = await load_cypherfix_settings(self.state.project_id)
        self._settings_dict = settings_dict  # Keep raw dict for LLM key resolution
        if settings_dict:
            self.state.settings = CodeFixSettings(**{
                k: v for k, v in settings_dict.items()
                if k in CodeFixSettings.model_fields
            })
        logger.info(f"[SETTINGS] repo={self.state.settings.github_repo}, "
                     f"branch={self.state.settings.default_branch}, "
                     f"model={self.state.settings.model}, "
                     f"max_iterations={self.state.settings.max_iterations}, "
                     f"require_approval={self.state.settings.require_approval}")

        # Load remediation
        await self.callback.on_phase("cloning_repo", "Loading remediation details...")
        remediation = await self._load_remediation(remediation_id)
        if not remediation:
            logger.error(f"Remediation {remediation_id} not found")
            await self.callback.on_error("Remediation not found", recoverable=False)
            return
        self.state.remediation_title = remediation.get("title", "")
        logger.info(f"[REMEDIATION] title: {self.state.remediation_title or 'N/A'}")
        logger.info(f"[REMEDIATION] type: {remediation.get('remediationType', 'N/A')}, "
                     f"severity: {remediation.get('severity', 'N/A')}")
        logger.debug(f"[REMEDIATION FULL]\n{json.dumps(remediation, indent=2, default=str)}")

        # Update status (clear agentNotes from previous runs)
        await self._update_remediation(remediation_id, {
            "status": "in_progress",
            "agentSessionId": self.state.session_id,
            "agentNotes": "",
        })

        # Clone repo
        await self.callback.on_phase("cloning_repo", "Cloning repository...")
        try:
            self.repo_manager = GitHubRepoManager(
                token=self.state.settings.github_token,
                repo=self.state.settings.github_repo or remediation.get("targetRepo", ""),
                default_branch=self.state.settings.default_branch,
            )
            logger.info(f"Cloning {self.repo_manager.repo} (branch: {self.state.settings.default_branch})...")
            repo_path = self.repo_manager.clone()
            self.state.repo_path = repo_path
            self.state.base_branch = self.state.settings.default_branch
            logger.info(f"Clone successful — path: {repo_path}")

            # Create fix branch
            branch_name = f"{self.state.settings.branch_prefix}{remediation_id}"
            self.repo_manager.create_branch(branch_name)
            self.state.branch_name = branch_name
            logger.info(f"Fix branch created: {branch_name}")
        except Exception as e:
            logger.error(f"Clone failed: {e}")
            await self.callback.on_error(f"Clone failed: {e}", recoverable=False)
            return

        # Get repo structure
        await self.callback.on_phase("exploring_codebase", "Starting analysis...")
        repo_structure = await github_list_dir(self.state)
        logger.debug(f"[REPO STRUCTURE]\n{repo_structure[:5000]}")

        # Init LLM
        self.llm_client = await self._init_llm()
        logger.info(f"[LLM] Initialized: {self.state.settings.model}")

        # Build system prompt
        system_prompt = build_codefix_system_prompt(
            remediation, repo_structure, self.state.settings,
        )
        logger.debug(f"[SYSTEM PROMPT] ({len(system_prompt)} chars)\n{system_prompt[:3000]}")

        # Build initial messages
        messages = [{
            "role": "user",
            "content": (
                "Fix the vulnerability described in the system prompt. "
                "Start by exploring the codebase to understand the architecture, "
                "then implement the fix."
            ),
        }]
        logger.info(f"[START] Entering ReAct loop (max {self.state.settings.max_iterations} iterations)")

        # ReAct loop
        iteration = 0
        max_iterations = self.state.settings.max_iterations
        SEP = "=" * 80

        while iteration < max_iterations and self.state.status != "error":
            iteration += 1
            self.state.iteration = iteration
            logger.info(f"\n{SEP}\n  REACT ITERATION {iteration}/{max_iterations}\n{SEP}")

            # Inject guidance if any
            if self.guidance_messages:
                guidance = "\n".join(self.guidance_messages)
                messages.append({"role": "user", "content": f"[User guidance]: {guidance}"})
                logger.info(f"[GUIDANCE] User guidance injected:\n{guidance}")
                self.guidance_messages.clear()

            # Call LLM
            try:
                response = await self._call_llm(system_prompt, messages)
            except Exception as e:
                logger.error(f"[LLM ERROR] Call failed (iteration {iteration}): {e}")
                if iteration < 3:
                    await asyncio.sleep(min(2 ** iteration, 30))
                    continue
                await self.callback.on_error(f"LLM error: {e}", recoverable=False)
                break

            # Append assistant message (include tool_uses so _call_llm can reconstruct properly)
            messages.append({
                "role": "assistant",
                "content": response["content"],
                "tool_uses": response.get("tool_uses", []),
            })

            # Extract and log full LLM reasoning
            llm_text_parts = []
            if isinstance(response["content"], list):
                for block in response["content"]:
                    if isinstance(block, dict) and block.get("type") == "text" and block["text"].strip():
                        llm_text_parts.append(block["text"].strip())
                        await self.callback.on_thinking(block["text"][:20000])
            elif isinstance(response["content"], str) and response["content"].strip():
                llm_text_parts.append(response["content"].strip())
                await self.callback.on_thinking(response["content"][:20000])

            llm_text = "\n".join(llm_text_parts)
            if llm_text:
                self.last_llm_text = llm_text
                logger.debug(f"[LLM REASONING]\n{llm_text}")
                logger.info(f"[LLM REASONING] ({len(llm_text)} chars): {llm_text[:300]}{'...' if len(llm_text) > 300 else ''}")

            # Check stop condition — LLM decided to stop
            if response.get("stop_reason") == "end_turn" and not response.get("tool_uses"):
                logger.info(f"[LLM STOP] end_turn — no tool calls")
                if llm_text:
                    logger.info(f"[LLM FINAL CONCLUSION]\n{llm_text}")
                else:
                    logger.info("[LLM FINAL CONCLUSION] (empty — no text response)")
                break

            # Execute tool calls
            tool_uses = response.get("tool_uses", [])
            if not tool_uses:
                logger.info(f"[LLM STOP] No tool calls returned")
                if llm_text:
                    logger.info(f"[LLM FINAL CONCLUSION]\n{llm_text}")
                else:
                    logger.info("[LLM FINAL CONCLUSION] (empty — no text response)")
                break

            tool_names = [tu["name"] for tu in tool_uses]
            logger.info(f"[TOOL CALLS] {len(tool_uses)} tool(s): {', '.join(tool_names)}")

            # Log full input for each tool call
            for i, tu in enumerate(tool_uses, 1):
                input_json = json.dumps(tu["input"], indent=2, default=str)
                logger.debug(f"[TOOL INPUT {i}/{len(tool_uses)}] {tu['name']} (id={tu['id']})\n{input_json}")

            tool_results = []
            parallel_tasks = []
            sequential_tasks = []

            for tu in tool_uses:
                if tu["name"] in SEQUENTIAL_TOOLS:
                    sequential_tasks.append(tu)
                else:
                    parallel_tasks.append(tu)

            # Execute parallel tools
            if parallel_tasks:
                results = await asyncio.gather(*[
                    self._execute_tool(tu) for tu in parallel_tasks
                ], return_exceptions=True)
                for tu, result in zip(parallel_tasks, results):
                    tool_results.append(self._format_tool_result(tu, result))

            # Execute sequential tools
            for tu in sequential_tasks:
                result = await self._execute_tool(tu)
                tool_results.append(self._format_tool_result(tu, result))

                # Handle approval
                if self.state.pending_approval and self.state.settings.require_approval:
                    await self.callback.on_phase("awaiting_approval", "Waiting for review...")
                    logger.info(f"[APPROVAL] Waiting for user decision on block {self.state.pending_block_id}...")
                    decision = await self._await_block_approval()

                    block_id = self.state.pending_block_id
                    if decision and decision.get("decision") == "reject":
                        reason = decision.get("reason", "No reason given")
                        logger.info(f"[APPROVAL] Block {block_id} REJECTED — reason: {reason}")
                        tool_results[-1] = {
                            "type": "tool_result",
                            "tool_use_id": tu["id"],
                            "content": (
                                f"Edit REJECTED by user. Reason: {reason}\n"
                                "Please revise your approach based on this feedback."
                            ),
                            "is_error": True,
                        }
                        if block_id:
                            await self.callback.on_block_status(block_id, "rejected")
                    else:
                        logger.info(f"[APPROVAL] Block {block_id} ACCEPTED")
                        if block_id:
                            await self.callback.on_block_status(block_id, "accepted")
                    self.state.pending_approval = False
                    self.state.pending_block_id = None
                    await self.callback.on_phase("implementing_fix", "Continuing...")

            messages.append({"role": "user", "content": tool_results})

        # Finalize
        await self._finalize(remediation_id)

    async def _execute_tool(self, tool_use: dict) -> str:
        """Execute a single tool. Errors returned as strings, never raised."""
        tool_name = tool_use["name"]
        tool_input = tool_use["input"]

        await self.callback.on_tool_start(tool_name, tool_input)

        # Log full tool input
        input_json = json.dumps(tool_input, indent=2, default=str)
        logger.info(f"[TOOL START] {tool_name}")
        logger.debug(f"[TOOL INPUT] {tool_name}\n{input_json}")
        # Short summary at INFO for quick reading
        if tool_name in ("github_read", "github_edit", "github_write"):
            logger.info(f"  file: {tool_input.get('file_path', 'N/A')}")
        elif tool_name == "github_grep":
            logger.info(f"  pattern: {tool_input.get('pattern', 'N/A')}, include: {tool_input.get('include', '*')}")
        elif tool_name == "github_glob":
            logger.info(f"  pattern: {tool_input.get('pattern', 'N/A')}")
        elif tool_name == "github_bash":
            logger.info(f"  cmd: {str(tool_input.get('command', ''))[:200]}")

        try:
            handler = TOOL_HANDLERS.get(tool_name)
            if not handler:
                logger.warning(f"[TOOL ERROR] Unknown tool: {tool_name}")
                return f"Error: Unknown tool: {tool_name}"

            result = await handler(state=self.state, **tool_input)

            if len(result) > self.max_output_chars:
                result = (
                    result[:self.max_output_chars] +
                    f"\n\n[OUTPUT TRUNCATED — {self.max_output_chars} of {len(result)} chars]"
                )

            logger.info(f"[TOOL DONE] {tool_name} — ok ({len(result)} chars)")
            logger.debug(f"[TOOL OUTPUT] {tool_name}\n{result}")
            await self.callback.on_tool_complete(tool_name, True, result[:500])
            return result

        except Exception as e:
            error_msg = f"Error: {type(e).__name__}: {str(e)}"
            logger.error(f"[TOOL FAILED] {tool_name} — {error_msg}")
            await self.callback.on_tool_complete(tool_name, False, error_msg)
            return error_msg

    def _format_tool_result(self, tool_use: dict, result) -> dict:
        if isinstance(result, Exception):
            return {
                "type": "tool_result",
                "tool_use_id": tool_use["id"],
                "content": f"Error: {result}",
                "is_error": True,
            }
        return {
            "type": "tool_result",
            "tool_use_id": tool_use["id"],
            "content": str(result),
        }

    async def _await_block_approval(self, timeout: float = 300) -> Optional[dict]:
        """Wait for user to accept/reject a diff block."""
        loop = asyncio.get_event_loop()
        self.approval_future = loop.create_future()
        try:
            return await asyncio.wait_for(self.approval_future, timeout=timeout)
        except asyncio.TimeoutError:
            return {"decision": "accept"}  # Auto-accept on timeout
        finally:
            self.approval_future = None

    async def _finalize(self, remediation_id: str):
        """Commit, push, create PR if edits were made."""
        SEP = "=" * 80
        logger.info(f"\n{SEP}\n  FINALIZE\n{SEP}")
        logger.info(f"Iterations completed: {self.state.iteration}")
        logger.info(f"Files modified: {list(self.state.files_modified) if self.state.files_modified else 'NONE'}")
        logger.info(f"Diff blocks: {len(self.state.diff_blocks)}")

        if self.state.files_modified and self.repo_manager:
            try:
                rem_title = self.state.remediation_title or "security remediation"
                title = f"fix: {rem_title}"
                logger.info(f"Committing {len(self.state.diff_blocks)} change(s)...")
                for i, block in enumerate(self.state.diff_blocks, 1):
                    logger.info(f"  Change {i}: {block.file_path} ({block.status})")
                self.repo_manager.commit(title)
                logger.info(f"Pushing branch {self.state.branch_name}...")
                self.repo_manager.push(self.state.branch_name)
                logger.info("Creating pull request...")

                pr_data = self.repo_manager.create_pr(
                    title=title,
                    body=(
                        "Automated security fix by CypherFix.\n\n"
                        f"Remediation ID: {remediation_id}"
                    ),
                    branch=self.state.branch_name,
                )

                logger.info(f"PR created: {pr_data.get('pr_url', 'N/A')}")
                await self.callback.on_pr_created(pr_data)
                await self._update_remediation(remediation_id, {
                    "status": "pr_created",
                    "prUrl": pr_data["pr_url"],
                    "prStatus": "open",
                    "fixBranch": self.state.branch_name,
                    "fileChanges": [b.model_dump() for b in self.state.diff_blocks],
                })
                self.state.status = "completed"
                await self.callback.on_complete(remediation_id, "pr_created", pr_data["pr_url"])
            except Exception as e:
                logger.error(f"PR creation failed: {e}")
                await self._update_remediation(remediation_id, {
                    "status": "pending",
                    "agentSessionId": "",
                    "agentNotes": f"Push/PR failed: {e}",
                })
                await self.callback.on_error(f"PR creation failed: {e}", recoverable=False)
                self.state.status = "error"
                await self.callback.on_complete(remediation_id, "error")
        else:
            logger.info("No files were modified — completing without PR")
            logger.info("The LLM explored the repo but decided no code changes were needed/possible.")
            logger.info("Check [LLM FINAL CONCLUSION] above for the LLM's reasoning.")

            # Truncate to 2000 chars for DB storage
            agent_notes = self.last_llm_text[:20000] if self.last_llm_text else "Agent completed without making changes (no reasoning captured)."
            await self._update_remediation(remediation_id, {
                "status": "no_fix",
                "agentSessionId": "",
                "agentNotes": agent_notes,
            })
            self.state.status = "completed"
            await self.callback.on_complete(remediation_id, "no_fix")

    async def _load_remediation(self, remediation_id: str) -> Optional[dict]:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"{WEBAPP_API_URL}/api/remediations/{remediation_id}", headers=INTERNAL_HEADERS)
                resp.raise_for_status()
                return resp.json()
        except Exception as e:
            logger.error(f"Failed to load remediation: {e}")
            return None

    async def _update_remediation(self, remediation_id: str, data: dict):
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.put(
                    f"{WEBAPP_API_URL}/api/remediations/{remediation_id}", json=data,
                    headers=INTERNAL_HEADERS,
                )
        except Exception as e:
            logger.error(f"Failed to update remediation: {e}")

    async def _init_llm(self):
        """Initialize LLM client using centralized setup_llm."""
        from orchestrator_helpers.llm_setup import setup_llm, _resolve_provider_key

        model = self.state.settings.model
        logger.info(f"Setting up codefix LLM: {model}")

        settings = getattr(self, '_settings_dict', {}) or {}
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

    async def _call_llm(self, system: str, messages: list) -> dict:
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

        llm = self.llm_client.bind_tools([
            {"name": t["name"], "description": t["description"], "parameters": t["input_schema"]}
            for t in CODEFIX_TOOLS
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

    def add_guidance(self, message: str):
        """Add user guidance to be injected in next iteration."""
        self.guidance_messages.append(message)

    async def cleanup(self):
        """Clean up resources and reset stuck in_progress remediations."""
        # Reset remediation status if it's still in_progress (disconnected before completion)
        if self.state.remediation_id and self.state.status != "completed":
            try:
                await self._update_remediation(self.state.remediation_id, {
                    "status": "pending",
                    "agentSessionId": "",
                })
                logger.info(f"Reset remediation {self.state.remediation_id} to pending (session interrupted)")
            except Exception as e:
                logger.error(f"Failed to reset remediation status: {e}")

        if self.repo_manager:
            logger.info("Cleaning up cloned repository")
            self.repo_manager.cleanup()

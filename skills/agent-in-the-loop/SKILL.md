---
name: agent-in-the-loop
description: >
  Agent in the Loop: the pseudo-model loop/mcp makes every model call of a chat run a
  step that an external MCP client (Claude Code, Codex) answers over the inbound MCP
  server. A loop model must answer only inside its own run scope, never wait outside one,
  never be retried, and never let the outside brain approve its own dangerous actions.
  Trigger: editing agentic/agent_in_the_loop/; adding a model call site or a retry loop in
  the agent; adding a path that builds an LLM from a model id; editing
  webapp/src/lib/mcp/loop*.ts, webapp/src/lib/agentInTheLoop.ts, or the LOOP_STATUS
  handling in the chat drawer.
license: MIT
metadata:
  author: redamon
  version: "1.0.0"
  scope: [root, agentic, webapp]
  auto_invoke:
    - "Editing the Agent in the Loop broker, adapter, routes or loop MCP tools"
    - "Adding an agent model call site, a retry loop, or a path that builds an LLM from a model id"
---

## When to Use

- Changing the step broker, the adapter, the prompt document or the `/loop/*` routes.
- Adding a model call to the agent, or a loop that retries model calls.
- Adding any endpoint, job or feature that builds a chat model from a model id.
- Changing the loop MCP tools, their scope, the driver-token rule, or the drawer's loop status.

---

## Critical Rules

- **A loop model answers ONLY inside a live run scope of its session that uses the loop.**
  Its identity comes from `get_broker().scope_for_session(current_log_session_id)`, never
  from `current_user_id`, `current_project_id` or `current_session_id`: initialize_node
  calls the guardrail and the classifier before any node sets those
  ([model.py](../../agentic/agent_in_the_loop/model.py), [agent_context.py](../../agentic/agent_context.py)).
- **A new path that builds an LLM from a model id refuses `loop/`** with
  `refuse_loop_model()` / `LoopModelNotSupportedHere` (code `loop_model_not_supported_here`):
  no chat run, no driver, a wait that never ends ([llm_builder.py](../../agentic/llm_builder.py),
  the `api.py` builders). Feature pickers filter it with `excludeLoop`, saves refuse it.
- **Loop errors are never retried.** They carry `no_retry = True` and their messages contain
  no transient phrase (`timeout`, `connection`, a bare 5xx); `is_transient_llm_error` checks
  the marker first. A new loop that retries on ANY exception must `break` on
  `getattr(e, "no_retry", False)` ([errors.py](../../agentic/agent_in_the_loop/errors.py),
  [phase.py](../../agentic/orchestrator_helpers/phase.py) is the example).
- **A new model call site gets an `llm_purpose(...)` label**, or its step reaches the driver
  as `other` with a `text` answer format ([purpose.py](../../agentic/agent_in_the_loop/purpose.py)).
- **A loop run follows the project's `REQUIRE_TOOL_CONFIRMATION`, and an unattended run
  shows it.** The gates read the setting as in a provider run; `_stream_graph` passes it to
  `run_scope(tool_confirmation=...)`, the drawer's `loop_status` carries it as
  `toolConfirmation`, and `false` puts a red risk icon next to the Agent in the Loop chip
  ([loopStatus.ts](../../webapp/src/app/graph/components/AIAssistantDrawer/hooks/loopStatus.ts)).
  It stays out of the driver's view and the step (a step change bumps `contractVersion`).
- **Only a person answers approvals, questions and dangerous-tool confirmations.** No MCP
  tool may answer them ([loopTools.ts](../../webapp/src/lib/mcp/loopTools.ts)).
- **A driver token holds no write or exec scope besides `agent:loop`.** Compute it from
  `MCP_SCOPE_COPY` with `loopTokenProblem`, never a hand list; the loop tools refuse wider
  tokens ([loopScopes.ts](../../webapp/src/lib/mcp/loopScopes.ts)).
- **A person picks the brain.** MCP writes, presets, imports and user defaults never set a
  loop model (`loopModelRefusal`, the preset checks, `rememberedDefaults`).
- **Any change to the step shape bumps `contractVersion`** (agent `CONTRACT_VERSION`, the
  skill pack's `LOOP_CONTRACT_VERSION`), so a client's out-of-date skill says so.
- **A new loop tool** joins `LOOP_TOOL_NAMES` (withdrawn while the switch is off), every MCP
  test that stubs `MCP_KALI_EXEC_ENABLED` also stubs `AGENT_IN_THE_LOOP_ENABLED`, then
  `npm run docs:mcp` (the `mcp-server-tools` skill).
- **`loop_status` and the step views carry no prompt or answer text**; the WebSocket frame
  is sent, never persisted.

---

## Where things live

| Concern | File |
| --- | --- |
| Switch, tunables, `is_loop_model`, `is_loop_llm` | `agentic/agent_in_the_loop/__init__.py` |
| Steps, leases, deadlines, no-driver rule, dedup, pruning | `agentic/agent_in_the_loop/broker.py` |
| Run scope around every streaming graph loop | `AgentOrchestrator._stream_graph` in `agentic/orchestrator.py` |
| MCP tools, client, driver-token rule | `webapp/src/lib/mcp/loopTools.ts`, `loopClient.ts`, `loopScopes.ts` |
| Skill pack per client | `webapp/src/lib/mcp/loopSkill.ts` |
| Drawer status strings | `webapp/src/app/graph/components/AIAssistantDrawer/hooks/loopStatus.ts` |

## Resources

- [docs/readmes/README.MCP.SERVER.md](../../docs/readmes/README.MCP.SERVER.md) - the inbound MCP server and its security model
- The wiki page `Agent-in-the-Loop` - setup for Claude Code and Codex, how it works, limits
- Related skills: `llm-provider-integration`, `mcp-server-tools`, `redamon-testing`

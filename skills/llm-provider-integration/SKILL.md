---
name: llm-provider-integration
description: >
  Adding an LLM provider to RedAmon: the credential boundary (keys must never
  reach scan containers), prefix-routed model ids, and the provider registry. A
  misrouted model id or a leaked key are the two failures this guards.
  Trigger: adding or editing an LLM provider; editing parse_model_provider in
  agentic/orchestrator_helpers/llm_setup.py, the webapp provider-type registry,
  the user_llm_providers model, or an LLM call site that passes an API key; a
  non-chat provider type (TypeSafe Jev) or a path that picks "any provider row".
license: MIT
metadata:
  author: redamon
  version: "1.1.0"
  scope: [agentic, webapp]
  auto_invoke:
    - "Adding or integrating an LLM provider"
    - "Editing model-id routing or provider credential handling"
    - "Adding a non-chat provider type, or a path that picks any provider row"
---

## When to Use

- Adding a new LLM provider (OpenAI-compatible or otherwise) the agent can use.

For a non-LLM external API *tool*, use `agentic-tool-integration`.

---

## Critical Rules

- **NEVER let a provider API key reach a scan container.** Keys live in exactly
  two places: Postgres `user_llm_providers` and `instance_llm_providers` rows and,
  in transit, on the wire between webapp and agent. The recon / scan / MCP
  containers must **never** see them. Do not thread a provider key through recon
  settings or container env.
- **An instance provider reaches the agent only as a marked row of the owner's
  list.** `GET /api/users/{id}/llm-providers?internal=true` (master key) appends
  the providers Root assigned to a set the account holds, with `providerType:
  "instance"` and the kind in `instanceProviderType`, so no "the account's openai
  key" or "first custom provider" reader lands on one. Such a row serves only
  `instance/<providerId>/<model>`, resolved exactly (`exact_model_provider`,
  `instance_build_args` in [agentic/llm_builder.py](../../agentic/llm_builder.py));
  an `instance/` id the list lacks is refused in `setup_llm`
  (`instance_provider_unavailable`), never routed on to OpenAI.
- **NEVER add a model id that is not prefix-routed.** Anything other than
  `claude-*` and bare OpenAI ids MUST carry a `provider/<model>` prefix, resolved by
  `parse_model_provider()` in
  [agentic/orchestrator_helpers/llm_setup.py](../../agentic/orchestrator_helpers/llm_setup.py).
  An unprefixed id routes to the wrong provider silently. `loop/` is NOT a provider: it is
  Agent in the Loop (an external MCP client answers), and every builder outside a chat
  run refuses it (`refuse_loop_model`, the `agent-in-the-loop` skill).
- **NEVER treat every `user_llm_providers` row as a chat LLM.** A non-chat type
  (`jev` for TypeSafe and `jev_openrouter` for native Jev on OpenRouter) must be skipped by every path that
  builds a chat model, or its token is sent to the wrong host: `setup_llm`'s
  custom branch builds `ChatOpenAI(api_key=<row key>)` with no base URL, which is
  api.openai.com. Add the type to `NON_CHAT_PROVIDER_TYPES` in BOTH twins
  (`agentic/llm_builder.py`, `webapp/src/lib/llmProviderKinds.ts`); use
  `chat_providers()` / `isChatProvider` wherever rows are listed, counted, gated
  or forwarded (the `/api/models` forward, the project LLM gate, the triage
  preflight, the feature-model grid); and never let a stale `custom/<id>` fall
  back to "the first provider" (`custom_provider_or_fallback` falls back only to
  custom-capable types). `setup_llm` also refuses a non-chat type outright.
- **A non-chat provider's endpoint is a constant, and its type is locked.**
  `agentic/jev_client.py` owns the fixed TypeSafe and OpenRouter System One
  endpoints: pinned Jev 1.13, no redirects, retries or provider failover, and fixed
  error texts. POST forces model, URL and headers; multiple named Jev rows per
  account are allowed. PUT and the test route refuse a type change and ignore
  body-supplied URL/headers for a stored row, so a token cannot be re-pointed.
  Every project explicitly selects its owner's Jev row via `jevProviderId`;
  null never means the first row. Legacy/unconfigured projects use deterministic
  fallbacks until a selection is saved. Imports and presets never carry this id.
- **ALWAYS register the provider in the webapp provider-type registry** and
  **propagate the key kwarg into every LLM call site.** A provider registered but
  not propagated builds a client with no credentials. The guide enumerates all
  11 integration points; touch each.

---

## The two invariants

| Invariant | Where | Failure if broken |
| --- | --- | --- |
| Keys only in Postgres + webapp<->agent transit | [webapp/prisma/schema.prisma](../../webapp/prisma/schema.prisma) `user_llm_providers`; agent settings fetch | key leaks into scan/MCP containers |
| Model id prefix routing | `parse_model_provider()` in [llm_setup.py](../../agentic/orchestrator_helpers/llm_setup.py) | model routes to the wrong provider |

## Commands

```bash
docker compose build agent && docker compose up -d agent   # agentic/ is baked
docker compose exec webapp npx prisma db push              # provider schema changes (NEVER prisma migrate)
```

## Resources

- [docs/readmes/coding_agent_prompts/PROVIDER_INTEGRATION_GUIDELINES.md](../../docs/readmes/coding_agent_prompts/PROVIDER_INTEGRATION_GUIDELINES.md) - the 11 integration points, decision tree, and model-id prefix table
- Related skill: `agentic-tool-integration`

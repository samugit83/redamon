# LLM Provider Integration Guidelines

> Audience: an AI coding agent (or a human engineer) preparing a PR that adds a **brand-new LLM provider** to RedAmon end-to-end.
>
> Read this entire document before you touch a single file. The integration is **cross-stack** (Next.js + React + Prisma + FastAPI + LangChain + the recon pipeline + the kali-sandbox/redagraph/MCP layer + the CypherFix orchestrators). Skipping any one section will produce a half-wired provider that appears in the dropdown but silently fails on certain features.

---

## Table of Contents

1. [Architecture in one page](#1-architecture-in-one-page)
2. [What "fully integrated" means (acceptance criteria)](#2-what-fully-integrated-means-acceptance-criteria)
3. [Decision tree: classify your provider first](#3-decision-tree-classify-your-provider-first)
4. [The 11 integration points](#4-the-11-integration-points)
   - 4.1 Webapp - provider type registry
   - 4.2 Webapp - SVG brand icon
   - 4.3 Webapp - `LlmProviderForm` config UI
   - 4.4 Webapp - `presets/generate` direct LLM call
   - 4.5 Prisma schema (only if your provider needs new columns)
   - 4.6 Agentic - `parse_model_provider` (prefix routing)
   - 4.7 Agentic - `setup_llm` (LangChain client factory)
   - 4.8 Agentic - `model_providers.py` (model discovery + `/models` aggregator)
   - 4.9 Agentic - propagate the new API key kwarg into every call site
   - 4.10 Recon pipeline (no code, but verify routing through agent)
   - 4.11 Redagraph / Kali sandbox / MCP servers (no code, verify text-to-cypher)
5. [Step-by-step PR checklist](#5-step-by-step-pr-checklist)
6. [Provider reference table](#6-provider-reference-table)
7. [Testing checklist](#7-testing-checklist)
8. [Common pitfalls](#8-common-pitfalls)
9. [Appendix - model ID conventions and prefix table](#9-appendix---model-id-conventions-and-prefix-table)

---

## 1. Architecture in one page

```
┌──────────────────────────────────────────────────────────────────────────┐
│ User browser                                                             │
│  ├── /settings  ──► LlmProviderForm picks a provider type, stores keys   │
│  └── Project form / AIAssistantDrawer ──► ModelPicker shows models       │
└──────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ Next.js webapp (Postgres-backed)                                         │
│  ├── prisma model UserLlmProvider  (per-user rows, plaintext apiKey)     │
│  ├── /api/users/:id/llm-providers (CRUD + ?internal=true unmasked)       │
│  ├── /api/models POST {userId} → forwards providers list to agent        │
│  ├── /api/projects/defaults → GET recon-orchestrator + agent /defaults   │
│  └── /api/presets/generate POST {userId, model, prompt}                  │
│       └── direct fetch() to provider HTTPS endpoint (no agent hop)       │
└──────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼ HTTP (with x-internal-key)
┌──────────────────────────────────────────────────────────────────────────┐
│ Agent container (FastAPI, LangChain) - agentic/                          │
│  ├── /defaults         agent-side defaults (camelCase to webapp)         │
│  ├── /models POST      fetch_all_models() across user's provider rows    │
│  ├── /roe/parse        RoE document understanding                        │
│  ├── /api/report/summarize    Report narratives                          │
│  ├── /text-to-cypher   Natural language → Cypher (graph queries)         │
│  ├── /llm/ffuf-extensions, /llm/nuclei-tags, /llm/nuclei-fp-filter,      │
│      /llm/waf-classify, /llm/takeover-classify                           │
│      (all "Enable AI in pipeline" features, called by recon over HTTP)   │
│  ├── /llm-provider/test    Validate a provider config without saving     │
│  ├── /ws/cypherfix-triage  WebSocket - Cypher query fix orchestrator     │
│  ├── /ws/cypherfix-codefix WebSocket - Cypher remediation orchestrator   │
│  └── Main /chat orchestrator (think_node, generate_response_node, ...)   │
│                                                                          │
│  Provider plumbing lives in:                                             │
│    orchestrator_helpers/llm_setup.py     - parse_model_provider, setup_llm│
│    orchestrator_helpers/model_providers.py - fetch_<provider>_models     │
│    orchestrator_helpers/llm_retry.py     - provider-agnostic retry policy│
└──────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼ HTTP (AGENT_API_URL env var)
┌──────────────────────────────────────────────────────────────────────────┐
│ Recon pipeline containers (recon, gvm_scan, github_secret_hunt, ...)     │
│  No LLM SDKs. No API keys. They just POST {model, user_id, project_id,   │
│  payload} to AGENT_API_URL/llm/*. All key resolution happens in agent.   │
└──────────────────────────────────────────────────────────────────────────┘
                                  ▲
                                  │
┌──────────────────────────────────────────────────────────────────────────┐
│ Kali sandbox (mcp/servers/*)                                             │
│  terminal_server, network_recon, metasploit, playwright, redagraph       │
│  → NO direct LLM calls. Redagraph delegates to agent /text-to-cypher.    │
└──────────────────────────────────────────────────────────────────────────┘
```

Three invariants you must respect:

1. **API keys live only in two places**: Postgres `user_llm_providers` rows (plaintext) and, in transit, on the wire between webapp and agent. Recon / scan / MCP containers must never see them.
2. **Model identifiers are prefix-routed strings**. Anything other than `claude-*` and bare OpenAI ids must carry a `provider/` prefix (see [§9](#9-appendix---model-id-conventions-and-prefix-table)).
3. **There is exactly one LangChain factory**: [agentic/orchestrator_helpers/llm_setup.py](../../../agentic/orchestrator_helpers/llm_setup.py) - `setup_llm()`. No other place in the agent should call `ChatOpenAI(...)` / `ChatAnthropic(...)` directly.

---

## 2. What "fully integrated" means (acceptance criteria)

A new provider is fully integrated when **every one** of the following works without code changes elsewhere:

- [ ] Provider appears as a card on `/settings` with an SVG icon, name, description, and "Get API key" link.
- [ ] The "Add Provider" wizard collects the right credential fields (API key only, or AWS triple, or base URL + headers).
- [ ] "Test Connection" round-trips through agent `/llm-provider/test` and returns a sample completion.
- [ ] After saving, models from this provider appear in every `ModelPicker` (project settings Agent Behaviour section, project settings Target section, AIAssistantDrawer top-bar selector).
- [ ] Selecting one of the new provider's models and running the agent chat works (think loop, tool calls, streaming, final response).
- [ ] Selecting one of the new provider's models for the **AI Pipeline Model** and toggling "Enable AI in Pipeline" makes all five recon AI hooks call your provider (FFuf extensions, Nuclei tags, Nuclei FP filter, WAF classifier, Takeover classifier).
- [ ] RoE document upload (`/api/roe/parse`) uses your provider when the project's `agentOpenaiModel` points at it.
- [ ] AI-generated preset (`/api/presets/generate`) uses your provider.
- [ ] Pentest report summarizer (`/api/report/summarize`) uses your provider.
- [ ] Text-to-Cypher (graph view "ask the graph" + redagraph MCP tool) uses your provider.
- [ ] The **inbound** MCP server's `query_graph` answers on a project whose model points at your provider. Mint a token in Global Settings -> MCP Server with `recon:read`, then call `query_graph` with a `question` (not a `cypher`). Same `/graph/nl-query` -> `_build_cypher_manager` -> `setup_llm` path as "ask the graph", so an unrecognised prefix in `parse_model_provider` breaks it for **every external agent at once** - and they are told `Could not turn that question into a query. Try rephrasing it.`, which sends them rewriting a question that was never the problem.
- [ ] CypherFix Triage + CodeFix WebSocket orchestrators use your provider when `cypherfixLlmModel` (or fallback `agentOpenaiModel`) points at it.
- [ ] Tradecraft URL verifier (`/tradecraft/verify`) uses your provider.

If any one of these silently falls back to OpenAI/Anthropic, you have missed a kwarg in `setup_llm()` call sites - see [§4.9](#49-agentic---propagate-the-new-api-key-kwarg-into-every-call-site).

---

## 3. Decision tree: classify your provider first

Before writing any code, answer these three questions. Each downstream change depends on the answer.

### Q1. Is the provider's HTTP API OpenAI-compatible?

By "OpenAI-compatible" we mean: `POST {baseUrl}/chat/completions` with `Authorization: Bearer <key>` and an `{model, messages, temperature, max_tokens}` body that returns `{choices: [{message: {content: "..."}}]}`.

| Provider | Compatible? | Base URL |
|---|---|---|
| OpenAI | yes | `https://api.openai.com/v1` |
| OpenRouter | yes (+ HTTP-Referer/X-Title headers) | `https://openrouter.ai/api/v1` |
| DeepSeek | yes | `https://api.deepseek.com/v1` |
| GLM (Zhipu) | yes | `https://open.bigmodel.cn/api/paas/v4` |
| Kimi (Moonshot) | yes | `https://api.moonshot.ai/v1` |
| Qwen (Alibaba) | yes | `https://dashscope-intl.aliyuncs.com/compatible-mode/v1` |
| xAI (Grok) | yes | `https://api.x.ai/v1` |
| Mistral | yes | `https://api.mistral.ai/v1` |
| Google Gemini | yes (`/v1beta/openai`) for presets; `langchain_google_genai` for agent | n/a |
| Anthropic | no - uses `/v1/messages`, `x-api-key`, blocks format | `https://api.anthropic.com` |
| AWS Bedrock | no - boto3 + AWS SigV4 + Converse API | n/a |

If **yes**, your work is mostly templated: copy the DeepSeek/xAI/Mistral pattern in every file. If **no**, expect to add bespoke branches in `setup_llm`, `model_providers.py`, and `webapp/src/app/api/presets/generate/route.ts`.

### Q2. Does the provider need credentials other than a single API key?

- **Just an API key** (the common case): one column (`apiKey`) on `UserLlmProvider`. No Prisma migration. Reuse the `isKeyBased` UI branch.
- **AWS-style credentials** (region + access key + secret): use the existing Bedrock columns. No Prisma migration unless your scheme differs.
- **OAuth, service account JSON, multi-key**: you need a Prisma migration. See [§4.5](#45-prisma-schema-only-if-your-provider-needs-new-columns).

### Q3. Does the provider expose a model-listing endpoint?

- **Yes, public** (e.g., OpenRouter): no API key required to list.
- **Yes, keyed** (e.g., OpenAI, Anthropic, DeepSeek): list with the user's key.
- **No** (rare): provide a hardcoded fallback list, e.g., `_DEEPSEEK_FALLBACK_MODELS` at [agentic/orchestrator_helpers/model_providers.py:160-285](../../../agentic/orchestrator_helpers/model_providers.py).

---

## 4. The 11 integration points

For each point, **read the referenced lines first**, then apply the change. The order below matches a natural left-to-right "user clicks then provider is called" flow.

### 4.1 Webapp - provider type registry

**File:** [webapp/src/lib/llmProviderPresets.ts](../../../webapp/src/lib/llmProviderPresets.ts) (canonical list at lines 66-79)

Add one entry to `PROVIDER_TYPES`:

```ts
{
  id: 'myprovider',                                    // lowercase, no spaces - used everywhere as providerType
  name: 'My Provider',                                 // display name
  description: 'One-line value prop shown on the card',
  Icon: SiMyProvider as ProviderIcon,                  // see §4.2 if not in react-icons
  apiKeyUrl: 'https://console.myprovider.com/api-keys' // empty string only for openai_compatible
}
```

Rules:
- `id` must match the value you will use in `parse_model_provider()` ([§4.6](#46-agentic---parse_model_provider-prefix-routing)) and in `_resolve_provider_key()` calls ([§4.9](#49-agentic---propagate-the-new-api-key-kwarg-into-every-call-site)).
- `id` is **persisted to Postgres** (`UserLlmProvider.providerType`) and read by Python - renaming it later is a breaking migration. Pick carefully.
- Do **not** import provider SDKs in this file; it is shipped to the browser.

### 4.2 Webapp - SVG brand icon

**File:** [webapp/src/components/icons/ProviderBrandIcons.tsx](../../../webapp/src/components/icons/ProviderBrandIcons.tsx)

Preferred order:

1. **If the brand has a `react-icons/si` (Simple Icons) entry**, import it directly in `llmProviderPresets.ts` (like `SiOpenai`, `SiAnthropic`, `SiGooglegemini`). No code change here.
2. **If not**, add a 24x24 viewBox SVG path inside `ProviderBrandIcons.tsx` and export it as `Si<Provider>`. Follow the existing pattern exactly:

   ```ts
   const MYPROVIDER_PATH = 'M0 3h5.5l6.5 10.5...'   // 24x24 viewBox, fill=currentColor

   export const SiMyProvider = (props: IconProps) => (
     <BrandSvg {...props} title={props.title ?? 'My Provider'} path={MYPROVIDER_PATH} />
   )
   ```

3. **Last resort**: use a generic Lucide icon (`LuSparkles`, `LuSettings`) - only acceptable for catch-all entries like `openai_compatible`.

Then import the new icon at the top of `llmProviderPresets.ts`:

```ts
import { SiDeepseek, SiOpenrouter, SiMoonshot, SiQwen, SiXai, SiMistral, SiMyProvider } from '@/components/icons/ProviderBrandIcons'
```

The icon is rendered at 40x40 inside the provider-type grid ([LlmProviderForm.tsx:169](../../../webapp/src/components/settings/LlmProviderForm.tsx#L169)) and at 16-20px inside settings list rows. Make sure the path renders cleanly at both sizes.

### 4.3 Webapp - `LlmProviderForm` config UI

**File:** [webapp/src/components/settings/LlmProviderForm.tsx](../../../webapp/src/components/settings/LlmProviderForm.tsx)

The form already auto-renders the provider card from `PROVIDER_TYPES` ([§4.1](#41-webapp---provider-type-registry)). What you must update is the **branch logic** at line 189 that decides which credential fields to show:

```ts
const isKeyBased = ['openai', 'anthropic', 'openrouter', 'deepseek', 'gemini',
                    'glm', 'kimi', 'qwen', 'xai', 'mistral'].includes(ptype)
const isBedrock = ptype === 'bedrock'
const isCompat  = ptype === 'openai_compatible'
```

Choose one of:

- **Single API key**: add `'myprovider'` to the `isKeyBased` array. No further UI change needed - the password input at [LlmProviderForm.tsx:227-247](../../../webapp/src/components/settings/LlmProviderForm.tsx#L227) handles it.
- **AWS-style credential triple**: reuse `isBedrock` branch if region + access key + secret is the right shape, otherwise add a new branch (`isMyProvider`) at line 250-280 and render your own field group.
- **OpenAI-compatible (user supplies baseUrl)**: nothing to do; users add it under the existing "OpenAI-Compatible" provider with one of the [OPENAI_COMPAT_PRESETS](../../../webapp/src/lib/llmProviderPresets.ts#L18) (Ollama, vLLM, LM Studio, Groq, Together AI, Fireworks, Mistral, Deepinfra, Custom). Only add a dedicated `PROVIDER_TYPES` entry if you can supply a default base URL **and** want first-class branding.

Also extend the "already added" guard if your provider should be singleton per user (default behavior: `existingProviderTypes.includes(pt.id)` at line 158 blocks duplicates; the only exception today is `openai_compatible`).

### 4.4 Webapp - `presets/generate` direct LLM call

**File:** [webapp/src/app/api/presets/generate/route.ts](../../../webapp/src/app/api/presets/generate/route.ts)

This route bypasses the agent and calls the provider directly from the Next.js server. **It must mirror `setup_llm()`'s routing**. Update three places:

1. **`resolveProviderType()`** at [route.ts:34-57](../../../webapp/src/app/api/presets/generate/route.ts#L34): add the prefix mapping.
   ```ts
   'myprovider/': 'myprovider',
   ```
2. **`defaultBaseUrlFor()`** at [route.ts:63-76](../../../webapp/src/app/api/presets/generate/route.ts#L63): add the base URL if OpenAI-compatible.
   ```ts
   case 'myprovider': return 'https://api.myprovider.com/v1'
   ```
3. **`friendlyNames`** at [route.ts:208-220](../../../webapp/src/app/api/presets/generate/route.ts#L208): so the "configure provider X in Global Settings" error message is user-friendly.

If your provider is **not** OpenAI-compatible (rare - only Anthropic and Bedrock today), add a third `call<Myprovider>()` function and branch at line 232 alongside `callAnthropic`. Bedrock is currently rejected with HTTP 400 at line 193-198 because Node-side SigV4 is painful - match that pattern if your provider has the same problem.

### 4.5 Prisma schema (only if your provider needs new columns)

**File:** [webapp/prisma/schema.prisma](../../../webapp/prisma/schema.prisma) (`UserLlmProvider` model at lines 31-62)

> Columns added here are on `UserLlmProvider`, **not** on `Project`, so they need
> no entry in `recon_settings/registry.yaml` and the registry build will not fire.
> That build compares against `Prisma.ProjectScalarFieldEnum` only. The
> project-level model pointers that *do* live on `Project` (`aiPipelineModel`,
> `agentOpenaiModel`) are already described there, as ordinary settable fields in
> the `llm` group — they choose a model, which is tuning, not a credential. The
> credentials themselves never become `Project` columns, which is the boundary
> that matters.

The schema already has all common fields:

| Column | Purpose |
|---|---|
| `apiKey` | Single-key providers (10 of the 11 existing types use this) |
| `baseUrl`, `modelIdentifier`, `defaultHeaders`, `timeout`, `temperature`, `maxTokens`, `sslVerify` | `openai_compatible` providers |
| `awsRegion`, `awsAccessKeyId`, `awsSecretKey`, `awsBearerToken` | Bedrock (IAM mode uses access key + secret; long-term API key mode uses `awsBearerToken`. The two are mutually exclusive at save time.) |

**Do not add new columns unless your provider needs a fundamentally new credential shape** (OAuth, JWT, service account JSON, multi-key rotation, etc.). Adding optional columns inflates the model for everyone.

If you genuinely need new columns:

1. Edit `schema.prisma`. Use `@default("")` for strings, `@default(false)` for booleans, `@map("snake_case")` for the SQL column name. Match the existing style.
2. Apply via push (this project never uses migrations - see project memory):
   ```bash
   docker compose exec webapp npx prisma db push
   ```
3. Update the masking logic in [webapp/src/app/api/users/[id]/llm-providers/route.ts](../../../webapp/src/app/api/users/%5Bid%5D/llm-providers/route.ts) `maskSecret()` to also mask the new secret-bearing column on GET responses.
4. Update the PUT `route.ts` to detect masked placeholders and preserve the prior value when the user submits the masked form unchanged.
5. Extend the `ProviderData` interface at [LlmProviderForm.tsx:18-33](../../../webapp/src/components/settings/LlmProviderForm.tsx#L18) and `EMPTY_PROVIDER` at [LlmProviderForm.tsx:35-49](../../../webapp/src/components/settings/LlmProviderForm.tsx#L35).

### 4.6 Agentic - `parse_model_provider` (prefix routing)

**File:** [agentic/orchestrator_helpers/llm_setup.py](../../../agentic/orchestrator_helpers/llm_setup.py) (`parse_model_provider`, near line 90)

Add your prefix branch in the existing `elif` chain:

```python
elif model_name.startswith("myprovider/"):
    return ("myprovider", model_name[len("myprovider/"):])
```

Rules:
- The string before the slash **must equal** the `id` you used in [§4.1](#41-webapp---provider-type-registry) and the `providerType` value stored in Postgres.
- Do not reuse a bare prefix that already maps elsewhere. The only "bare" mappings are `claude-*` to anthropic and everything-else to openai.
- `loop/` is taken and is **not a provider**: it is Agent in the Loop, where the person's own MCP client (Claude Code, Codex) answers the agent's model calls. It has no key, no `/models` fetch and no `setup_llm` provider branch beyond the adapter, and every builder outside a chat run refuses it (`refuse_loop_model`, the `agent-in-the-loop` skill). Never add a provider type named `loop`.
- This routing table is mirrored in TypeScript at [presets/generate/route.ts:34](../../../webapp/src/app/api/presets/generate/route.ts#L34). **Both must stay in sync** - drift between them was the cause of past bugs.

### 4.7 Agentic - `setup_llm` (LangChain client factory)

**File:** [agentic/orchestrator_helpers/llm_setup.py](../../../agentic/orchestrator_helpers/llm_setup.py) (`setup_llm` at lines 76-327)

Three sub-changes:

#### 4.7.a Add a new kwarg to the function signature

```python
def setup_llm(
    model_name: str,
    *,
    openai_api_key: str | None = None,
    anthropic_api_key: str | None = None,
    # ... existing kwargs ...
    myprovider_api_key: str | None = None,        # <-- ADD HERE
    aws_access_key_id: str | None = None,
    aws_secret_access_key: str | None = None,
    aws_region: str = "us-east-1",
    custom_llm_config: dict | None = None,
) -> BaseChatModel:
```

#### 4.7.b Add a provider branch in the dispatch chain

Place it before the final `anthropic` / `openai` fallbacks, matching the existing style. **Template for an OpenAI-compatible provider** (copy `mistral` at lines 270-280):

```python
elif provider == "myprovider":
    if not myprovider_api_key:
        raise ValueError(
            f"My Provider API key is required for model '{model_name}'"
        )
    llm = ChatOpenAI(
        model=api_model,
        api_key=myprovider_api_key,
        base_url="https://api.myprovider.com/v1",
        temperature=0,
    )
```

**Template for a non-OpenAI-compatible provider**: study the `anthropic` branch (lines 296-313) for `ChatAnthropic` with `max_retries=5`, `default_request_timeout=300.0`, and the conditional `temperature` (some Anthropic models reject the param - see `ANTHROPIC_NO_TEMPERATURE_MODELS` at lines 16-20). Study the `bedrock` branch (lines 282-294) for `ChatBedrockConverse`. If LangChain has no integration for your provider, see [§8](#8-common-pitfalls).

#### 4.7.c (Custom-tier integration, usually skip) update the `custom` branch

Lines 105-166 handle the `custom/` prefix, which is what users hit when they configure your provider under "OpenAI-Compatible" with a user-supplied baseUrl. The existing `openai_compatible` sub-branch already handles arbitrary baseUrls - touch this only if your provider has a non-OpenAI wire format and you want it usable from the `custom/` prefix too.

### 4.8 Agentic - `model_providers.py` (model discovery + `/models` aggregator)

**File:** [agentic/orchestrator_helpers/model_providers.py](../../../agentic/orchestrator_helpers/model_providers.py)

Two sub-changes:

#### 4.8.a Add a `fetch_<myprovider>_models()` async function

For an OpenAI-compatible provider with a working `/v1/models` endpoint, use the generic helper at lines 290-324:

```python
async def fetch_myprovider_models(api_key: str = "") -> list[dict]:
    if not api_key:
        return []
    discovered = await _fetch_openai_compat_models(
        base_url="https://api.myprovider.com/v1",
        api_key=api_key,
        id_prefix="myprovider",
        description="My Provider",
    )
    if not discovered:
        for mid, mname in _MYPROVIDER_FALLBACK_MODELS:
            discovered.append(_model(
                id=f"myprovider/{mid}",
                name=mname,
                description="My Provider",
            ))
    return discovered
```

And add a fallback list at the top (lines 160-285 hold the existing ones):

```python
_MYPROVIDER_FALLBACK_MODELS: list[tuple[str, str]] = [
    ("myprovider-large", "My Provider Large"),
    ("myprovider-small", "My Provider Small"),
]
```

Rules:
- The `id` returned to the webapp **must** carry the `myprovider/` prefix - this is what `ModelPicker` sends back as the selected model and what `parse_model_provider()` will then route on.
- Filter out non-chat models (embeddings, transcription, image, TTS) - see the OpenAI filter at lines 33-72 for the pattern.
- Sort by id descending so the newest model appears first (per existing convention).

For non-OpenAI-compatible providers, study `fetch_anthropic_models` (lines 78-105), `fetch_gemini_models` (lines 357-389), or `fetch_bedrock_models` (lines 395-453, uses `asyncio.to_thread` to wrap boto3).

#### 4.8.b Wire it into the `fetch_all_models()` switch

[model_providers.py:484-514](../../../agentic/orchestrator_helpers/model_providers.py#L484):

```python
elif ptype == "myprovider":
    tasks_db[f"My Provider ({pname})"] = fetch_myprovider_models(api_key=p.get("apiKey", ""))
```

The bracketed display name shows up as the group header in `ModelPicker`. Pick something readable - `"My Provider"` is fine; the trailing `({pname})` will include the per-row name the user gave when they saved the provider.

### 4.9 Agentic - propagate the new API key kwarg into every call site

**This is the step most likely to be missed.** `setup_llm()` is called from **seven** places, each of which independently resolves user providers and passes kwargs. If you miss one, that feature silently fails for your provider.

For each location below, add:

```python
myprovider_p = _resolve_provider_key(user_providers, "myprovider")
# ... and in the setup_llm call:
myprovider_api_key=(myprovider_p or {}).get("apiKey"),
```

| # | File | Function | Lines | Used by |
|---|---|---|---|---|
| 1 | [agentic/orchestrator_helpers/llm_setup.py](../../../agentic/orchestrator_helpers/llm_setup.py) | `apply_project_settings` | 341-405 | Main agent orchestrator (think loop, tool calls, generate response, fireteam, guardrail) |
| 2 | [agentic/api.py](../../../agentic/api.py) | `_build_llm_with_model_for_user` | 467-516 | All five `/llm/*` recon endpoints (FFuf, Nuclei tags, Nuclei FP, WAF, Takeover) |
| 3 | [agentic/api.py](../../../agentic/api.py) | `_setup_llm_for_endpoint` | 1094-1134 | `/roe/parse`, `/api/report/summarize`, (any endpoint that reads from cached orchestrator settings) |
| 4 | [agentic/api.py](../../../agentic/api.py) | `_build_llm_for_user` | 1148+ | `/tradecraft/verify`, plus other non-project endpoints |
| 5 | [agentic/api.py](../../../agentic/api.py) | `text_to_cypher` handler | ~2380-2462 | `/text-to-cypher` (graph view "ask the graph", redagraph MCP tool, Cypher generation inside agent tools) |
| 6 | [agentic/cypherfix_triage/orchestrator.py](../../../agentic/cypherfix_triage/orchestrator.py) | `__init__` | ~15-80 | `/ws/cypherfix-triage` WebSocket orchestrator |
| 7 | [agentic/cypherfix_codefix/orchestrator.py](../../../agentic/cypherfix_codefix/orchestrator.py) | `__init__` | ~15-80 | `/ws/cypherfix-codefix` WebSocket orchestrator |

**Grep to verify you got them all** before opening the PR:

```bash
# All call sites that pass per-provider kwargs to setup_llm:
grep -rn "openrouter_api_key=" agentic/
grep -rn "deepseek_api_key="   agentic/
grep -rn "mistral_api_key="    agentic/
# Then grep for the kwarg you just added - count must match.
grep -rn "myprovider_api_key=" agentic/
```

You can also grep for `_resolve_provider_key(.*,\s*"openrouter"` and ensure your provider has the same number of hits.

### 4.10 Recon pipeline (no code, but verify routing through agent)

**Files:** [recon/helpers/ai_planner/](../../../recon/helpers/ai_planner/) (5 files: `ffuf_extensions.py`, `nuclei_tags.py`, `nuclei_response_filter.py`, `waf_classifier.py`, `takeover_classifier.py`)

These files **contain no LLM SDK imports and no provider-specific branches**. They forward to `AGENT_API_URL/llm/*` with a JSON payload `{model, user_id, project_id, ...features}`. The agent does all provider resolution.

Therefore, **you do not edit any recon file**. But you must verify:

- The model the user selects in the AI Pipeline Model picker carries your `myprovider/` prefix.
- The `/llm/*` endpoints in `agentic/api.py` use `_build_llm_with_model_for_user` ([§4.9](#49-agentic---propagate-the-new-api-key-kwarg-into-every-call-site) row 2), which you have already updated.

A common failure mode: `ModelPicker` shows your model under group "My Provider", but the user has not yet configured your provider. The recon container will POST to `/llm/*`, the agent will fail to resolve a key, and recon will gracefully fall back to the static / disabled behavior. That is the designed degradation. Make sure your error log message inside `_build_llm_with_model_for_user`'s `setup_llm()` failure is human-readable - `ValueError("My Provider API key is required for model 'myprovider/foo'")` is what your `setup_llm` branch from [§4.7.b](#47b-add-a-provider-branch-in-the-dispatch-chain) raises.

### 4.11 Redagraph / Kali sandbox / MCP servers (no code, verify text-to-cypher)

**Files:** [mcp/servers/](../../../mcp/servers/) - `terminal_server.py`, `network_recon_server.py`, `metasploit_server.py`, `playwright_server.py`, `redagraph.py`

**None of these contain LLM calls.** Redagraph is the only one that triggers LLM behavior, and it does so by HTTP-calling agent's `/text-to-cypher` - which you already updated in [§4.9](#49-agentic---propagate-the-new-api-key-kwarg-into-every-call-site) row 5.

To verify after deploy: open the graph view, click "Ask the graph", switch the model to one of your provider's models in the project settings, and confirm a natural-language query produces a Cypher result.

**The INBOUND MCP server is a second consumer of that same path, and it is not in the file list above.** `mcp/servers/` is RedAmon as an MCP *client*; `webapp/src/lib/mcp/` + `/api/mcp-server` is RedAmon as an MCP *server*, where a third-party agent connects in with a personal access token. Its `query_graph` tool routes a `question` argument through the identical `/graph/nl-query` -> `_build_cypher_manager` -> `setup_llm` chain, so it needs no code change here either - but it is the surface where a routing miss is least visible, because the external agent sees only "try rephrasing" and has no way to reach your logs. The LLM spend is billed against the token owner's key and bounded per token. Verify it with the acceptance-criteria item in [§2](#2-what-fully-integrated-means-acceptance-criteria).

---

## 5. Step-by-step PR checklist

Follow this order exactly. Each step is small enough to verify in isolation.

### Phase A - Webapp UI (visible, no backend dependency)

1. Add icon to [`ProviderBrandIcons.tsx`](../../../webapp/src/components/icons/ProviderBrandIcons.tsx) (or skip if using a `react-icons/si` entry).
2. Add `PROVIDER_TYPES` entry in [`llmProviderPresets.ts`](../../../webapp/src/lib/llmProviderPresets.ts).
3. Add `id` to the `isKeyBased` array in [`LlmProviderForm.tsx`](../../../webapp/src/components/settings/LlmProviderForm.tsx) (or add a new credential branch if not key-based).
4. **Smoke test**: `/settings` shows the new card with the right icon, name, description. Wizard step 2 shows the right credential fields. Save creates a row in `user_llm_providers` (verify with `docker compose exec postgres psql -U postgres -d redamon -c 'select id, provider_type, name from user_llm_providers;'`).

### Phase B - Agent provider plumbing

5. Add prefix branch to [`parse_model_provider()`](../../../agentic/orchestrator_helpers/llm_setup.py#L27).
6. Add provider branch to [`setup_llm()`](../../../agentic/orchestrator_helpers/llm_setup.py#L76) with the new `myprovider_api_key` kwarg.
7. Add `fetch_myprovider_models()` in [`model_providers.py`](../../../agentic/orchestrator_helpers/model_providers.py) and wire it into [`fetch_all_models()`](../../../agentic/orchestrator_helpers/model_providers.py#L459).
8. Propagate the new kwarg to all five `agentic/api.py` call sites and the two CypherFix orchestrator `__init__` methods. See [§4.9](#49-agentic---propagate-the-new-api-key-kwarg-into-every-call-site) for the exact list.
9. Rebuild the agent: `docker compose build agent && docker compose up -d agent`.
10. **Smoke test**: `curl -X POST http://localhost:8090/models -H 'Content-Type: application/json' -d '{"providers":[{"id":"x","providerType":"myprovider","name":"test","apiKey":"<real>"}]}'` returns a non-empty list under `"My Provider (test)"`.

### Phase C - Webapp direct-call paths (preset generation)

11. Update [`presets/generate/route.ts`](../../../webapp/src/app/api/presets/generate/route.ts): `resolveProviderType`, `defaultBaseUrlFor`, `friendlyNames`. For non-OpenAI-compatible providers, add a dedicated `call<Myprovider>()` function and branch.
12. In dev mode the webapp hot-reloads. In prod: `docker compose build webapp && docker compose up -d webapp`.
12a. Register a usage probe for the new `providerType` in `LLM_PROBES` ([`webapp/src/lib/apiUsage/registry.ts`](../../../webapp/src/lib/apiUsage/registry.ts)), with its provider test next to it: a models listing that proves the key (see `providers/llm/validity.ts`), or a balance endpoint when the provider exposes one to a normal key. Never ask for an admin or management key just to show a number. `registry.drift.test.ts` fails until every `PROVIDER_TYPES` id has a probe.

### Phase D - End-to-end verification

13. Walk every acceptance criterion in [§2](#2-what-fully-integrated-means-acceptance-criteria). Open `/settings`, add the provider, "Test Connection". Open a project, switch the LLM model to one of your provider's models. Run an agent conversation. Toggle "Enable AI in Pipeline", select a recon-friendly model from your provider, kick off a scan, watch the recon SSE stream for `[Nuclei-AI]` / `[FFUF-AI]` / `[WAF-AI]` lines. Upload an RoE. Generate a preset from natural language. Try the graph view's "ask the graph". Trigger CypherFix on a failing Cypher.

### Phase E - Hygiene

14. Add the model id naming convention to your PR description so reviewers can verify.
15. **Do not commit real API keys** to fixtures or examples. Use placeholder strings like `"sk-FAKE-..."` in tests.
16. If you added a Prisma migration ([§4.5](#45-prisma-schema-only-if-your-provider-needs-new-columns)), call it out explicitly in the PR description - deployers must run `prisma db push` after pulling.
17. Update [CHANGELOG.md](../../../CHANGELOG.md) under the next version's `feat(provider)` entry.

---

## 6. Provider reference table

Use this table as a quick comparison. Every cell is a real value in today's codebase.

| Provider | `providerType` | LangChain class | Base URL / endpoint | Model prefix | Special headers / auth | Model discovery |
|---|---|---|---|---|---|---|
| OpenAI | `openai` | `ChatOpenAI` | `https://api.openai.com/v1` | (none - bare id) | `Authorization: Bearer` | `/v1/models`, filter `gpt-*`, `o1-*`, `o3-*`, `o4-*` |
| Anthropic | `anthropic` | `ChatAnthropic` | `https://api.anthropic.com` | `claude-*` (bare) | `x-api-key`, `anthropic-version` | `/v1/models?limit=100` |
| OpenRouter | `openrouter` | `ChatOpenAI` | `https://openrouter.ai/api/v1` | `openrouter/` | `Authorization: Bearer` + `HTTP-Referer: https://www.redamon.org`, `X-Title: RedAmon Agent` | public `/api/v1/models`, filter text I/O |
| DeepSeek | `deepseek` | `ChatOpenAI` | `https://api.deepseek.com/v1` | `deepseek/` | `Authorization: Bearer` | `/v1/models` + fallback list |
| Google Gemini | `gemini` | `ChatGoogleGenerativeAI` | `https://generativelanguage.googleapis.com` | `gemini/` | `?key=` query param | `/v1beta/models`, filter `models/gemini-*` with `generateContent` |
| GLM (Zhipu) | `glm` | `ChatOpenAI` | `https://open.bigmodel.cn/api/paas/v4` | `glm/` | `Authorization: Bearer` | OpenAI-compat `/models` + fallback |
| Kimi (Moonshot) | `kimi` | `ChatOpenAI` | `https://api.moonshot.ai/v1` | `kimi/` | `Authorization: Bearer` | OpenAI-compat `/models` + fallback |
| Qwen (Alibaba) | `qwen` | `ChatOpenAI` | `https://dashscope-intl.aliyuncs.com/compatible-mode/v1` | `qwen/` | `Authorization: Bearer` | OpenAI-compat `/models` + fallback |
| xAI (Grok) | `xai` | `ChatOpenAI` | `https://api.x.ai/v1` | `xai/` | `Authorization: Bearer` | OpenAI-compat `/models` + fallback |
| Mistral | `mistral` | `ChatOpenAI` | `https://api.mistral.ai/v1` | `mistral/` | `Authorization: Bearer` | OpenAI-compat `/models` + fallback |
| AWS Bedrock | `bedrock` | `ChatBedrockConverse` | (boto3, region-routed) | `bedrock/` | Two modes: SigV4 (IAM access key + secret + region) **or** Bedrock long-term API key (passed as `bedrock_api_key=` / `AWS_BEARER_TOKEN_BEDROCK`). Backend picks bearer when `awsBearerToken` is non-empty. | `bedrock.list_foundation_models(byOutputModality=TEXT, byInferenceType=ON_DEMAND)` |
| OpenAI-compatible (user supplies) | `openai_compatible` | `ChatOpenAI` | user-supplied | `custom/{providerConfigId}` | user-supplied headers | single entry, no discovery (`modelIdentifier` is the only model) |

---

## 7. Testing checklist

After your PR is wired up, run **all** of these. Do not mark the PR ready for review with a checkbox missing.

### Unit-ish (no scan needed)

- [ ] `docker compose exec agent python -c "from orchestrator_helpers.llm_setup import setup_llm; print(setup_llm('myprovider/some-model', myprovider_api_key='real-key'))"` returns a `BaseChatModel` without raising.
- [ ] `docker compose exec agent python -c "from orchestrator_helpers.llm_setup import parse_model_provider; print(parse_model_provider('myprovider/foo'))"` prints `('myprovider', 'foo')`.

### End-to-end clicks

- [ ] Add provider via `/settings`, test connection passes, save, row appears in `user_llm_providers` table.
- [ ] `/api/models` POST with that user id returns your provider group with at least one model.
- [ ] Project form (Agent Behaviour section) ModelPicker shows your models.
- [ ] Project form (Target section, "Enable AI in Pipeline" toggled on) shows your models in the AI Pipeline Model picker.
- [ ] AIAssistantDrawer top-bar model picker shows your models.
- [ ] Send a chat message, think loop runs, agent calls a tool, final response renders. (verify in logs: `LLM provider: myprovider, model: <id>`)
- [ ] Upload an RoE document, fields populate from your provider's parsing.
- [ ] Generate a preset from a natural-language prompt using one of your provider's models.
- [ ] Run a small scan with AI hooks on, check recon container logs for `[Nuclei-AI]`/`[FFUF-AI]`/`[WAF-AI]` lines showing successful agent calls.
- [ ] Open graph view, "ask the graph" with a Cypher question, Cypher executes.
- [ ] Trigger CypherFix on a broken Cypher, triage and codefix orchestrators both run.
- [ ] Submit a tradecraft URL on `/tradecraft`, verifier returns metadata.

### Resilience

- [ ] Delete the provider row mid-conversation, next agent invocation surfaces a clean `ValueError`, not a 500.
- [ ] Provide a wrong API key, the agent returns a 502 with a useful error message (not a `Traceback`).
- [ ] If your provider returns a transient 429 / 503, the agent retries (it relies on [`llm_retry.py`](../../../agentic/orchestrator_helpers/llm_retry.py) which classifies by exception class name and HTTP status, confirm your SDK raises types that match the `_TRANSIENT_EXC_NAMES` set or trip the `_TRANSIENT_STATUS_RE`).

---

## 8. Common pitfalls

1. **Forgetting one of the seven call sites in [§4.9](#49-agentic---propagate-the-new-api-key-kwarg-into-every-call-site).** Symptom: the agent main chat works, but RoE parse / preset / cypher-fix / one of the recon hooks "silently" complains about a missing key for an unrelated provider, because `_resolve_provider_key(providers, "myprovider")` returned `None` and the code defaulted to the OpenAI branch with no key.

2. **Drift between `parse_model_provider` (Python) and `resolveProviderType` (TypeScript).** Both must list the same prefixes. The TypeScript copy at [presets/generate/route.ts:34](../../../webapp/src/app/api/presets/generate/route.ts#L34) has a comment pointing back at the Python source, keep it accurate.

3. **Picking an `id` that conflicts with a model substring.** `parse_model_provider` matches by `startswith("myprovider/")`. If you name your provider `"openai_legacy"`, the bare-OpenAI fallback at the bottom of `parse_model_provider` will catch it first. Choose an id that does not begin with `claude-` or collide with the legacy `openai_compat/` prefix.

4. **Putting API keys in environment variables.** This is the legacy path that was already removed. Keys live in `user_llm_providers`. The recon containers and MCP servers must never receive them, only `AGENT_API_URL` and `WEBAPP_URL` env vars.

5. **Skipping the rebuild.** The agent container has Python source baked into the image. `docker compose restart agent` does NOT pick up a new `setup_llm()` branch. You must `docker compose build agent && docker compose up -d agent`. The webapp in dev mode hot-reloads; in prod it must be rebuilt as well.

6. **LangChain integration missing for your provider.** If your provider has no `langchain_<vendor>` package, the OpenAI-compatible adapter (`ChatOpenAI` with custom `base_url`) covers ~95% of providers. The remaining 5% (Anthropic-style block content, Gemini-style multimodal parts, Bedrock SigV4) need a dedicated LangChain class. Do not invent a new abstraction, open an upstream LangChain issue if no adapter exists yet, and as a stop-gap accept your provider only under the `openai_compatible` umbrella, with a clear note in the PR.

7. **Forgetting the model prefix in `fetch_<myprovider>_models()`.** Models returned without the `myprovider/` prefix will be parsed by `parse_model_provider()` as bare OpenAI, route to the OpenAI branch, and fail with "OpenAI API key is required". This is the single most common bug. Always prefix.

8. **Anthropic's `temperature` quirk.** Newer Claude models reject the `temperature` kwarg. The existing code guards via `ANTHROPIC_NO_TEMPERATURE_MODELS` at [llm_setup.py:16-20](../../../agentic/orchestrator_helpers/llm_setup.py#L16). If your provider has analogous per-model param quirks, add a similar set-and-guard pattern, do not hard-fail the whole provider.

9. **Stale model cache.** [model_providers.py:459](../../../agentic/orchestrator_helpers/model_providers.py#L459) has a `_cache` for the env-var fallback path but the DB-driven path is uncached. New models added by your provider appear immediately. No invalidation step needed.

10. **Using em dashes in user-facing strings.** Per project convention, never use em dashes in UI strings; they read as AI-generated. Use `:` or `-` instead. This applies to the `description` field in `PROVIDER_TYPES` and any prompt or error message you add.

---

## 9. Appendix - model ID conventions and prefix table

A model identifier as stored in `Project.agentOpenaiModel`, `Project.aiPipelineModel`, and `Project.cypherfixLlmModel` is one of:

- A bare OpenAI model id: `gpt-4-turbo`, `o3-mini`, `gpt-5` - routes to provider `openai`.
- A `claude-...` id: `claude-opus-4-7`, `claude-sonnet-4-6` - routes to provider `anthropic`.
- A prefixed id: `<prefix>/<vendor-model-id>` - routes to the prefix's provider.

| Prefix | Provider | Example |
|---|---|---|
| (none - `gpt-*` / `o*` etc.) | `openai` | `gpt-4-turbo` |
| (bare `claude-*`) | `anthropic` | `claude-opus-4-6` |
| `openrouter/` | `openrouter` | `openrouter/meta-llama/llama-4` |
| `bedrock/` | `bedrock` | `bedrock/anthropic.claude-3-5-sonnet-20240620-v1:0` |
| `deepseek/` | `deepseek` | `deepseek/deepseek-chat` |
| `gemini/` | `gemini` | `gemini/gemini-2.5-pro` |
| `glm/` | `glm` | `glm/glm-4-plus` |
| `kimi/` | `kimi` | `kimi/moonshot-v1-128k` |
| `qwen/` | `qwen` | `qwen/qwen-max` |
| `xai/` | `xai` | `xai/grok-3` |
| `mistral/` | `mistral` | `mistral/mistral-large-2411` |
| `custom/{configId}` | `openai_compatible` (per-user config) | `custom/clx7abc123` |
| `openai_compat/` (legacy) | env-var-driven OpenAI-compat | `openai_compat/llama3` |
| `loop/` | none: Agent in the Loop, an external MCP client answers (chat runs only) | `loop/mcp` |
| **your new prefix** | **your provider** | **`myprovider/myprovider-large`** |

When in doubt, the **single source of truth** is `parse_model_provider()` at [agentic/orchestrator_helpers/llm_setup.py:90](../../../agentic/orchestrator_helpers/llm_setup.py#L90). Any disagreement between this table and that function is a bug, fix the table, not the function.

---

## Quick file reference (everything you will touch)

**Webapp:**
- [webapp/src/lib/llmProviderPresets.ts](../../../webapp/src/lib/llmProviderPresets.ts) - provider registry
- [webapp/src/components/icons/ProviderBrandIcons.tsx](../../../webapp/src/components/icons/ProviderBrandIcons.tsx) - SVG brand icons
- [webapp/src/components/settings/LlmProviderForm.tsx](../../../webapp/src/components/settings/LlmProviderForm.tsx) - credential UI
- [webapp/src/app/api/presets/generate/route.ts](../../../webapp/src/app/api/presets/generate/route.ts) - direct LLM call (preset generation)
- [webapp/prisma/schema.prisma](../../../webapp/prisma/schema.prisma) - only if new columns

**Agent:**
- [agentic/orchestrator_helpers/llm_setup.py](../../../agentic/orchestrator_helpers/llm_setup.py) - `parse_model_provider`, `setup_llm`, `apply_project_settings`
- [agentic/orchestrator_helpers/model_providers.py](../../../agentic/orchestrator_helpers/model_providers.py) - model discovery, `/models` aggregator
- [agentic/api.py](../../../agentic/api.py) - call sites: `_build_llm_with_model_for_user`, `_setup_llm_for_endpoint`, `_build_llm_for_user`, text-to-cypher handler
- [agentic/cypherfix_triage/orchestrator.py](../../../agentic/cypherfix_triage/orchestrator.py) - CypherFix Triage `__init__`
- [agentic/cypherfix_codefix/orchestrator.py](../../../agentic/cypherfix_codefix/orchestrator.py) - CypherFix CodeFix `__init__`

**Never touched (verify only):**
- `recon/helpers/ai_planner/*.py` - HTTP delegation only
- `mcp/servers/*.py` - no LLM calls
- `recon_orchestrator/*.py` - no LLM calls

---
name: recon-ai-enrichment
description: >
  Wiring an LLM into a recon tool's decisions ("let AI pick {feature} for
  {tool}"): the never-raise contract, the per-target cache, the full+partial
  coverage, and the two UI toggles bound to one field. A raising AI helper or an
  empty fallback silently breaks or disables a live scan.
  Trigger: adding or editing a recon AI hook; a new
  recon/helpers/ai_planner/{tool}_{feature}.py; a /llm/{tool}-{feature} endpoint
  in agentic/api.py; a data.{tool}Ai{feature} toggle; editing
  apply_ai_pipeline_overrides in recon/project_settings.py; an LLM | Jev engine
  switch (a {tool}AiUseJev field, a /jev/* endpoint, agent_jev_gate); a
  Jev-only hook ({tool}Jev{Feature}, jev_shadow.py, shadow mode).
license: MIT
metadata:
  author: redamon
  version: "1.0.0"
  scope: [recon]
  auto_invoke:
    - "Wiring an LLM into a recon tool's decisions (AI in pipeline)"
    - "Adding or editing a recon/helpers/ai_planner hook or its /llm endpoint"
    - "Adding an LLM | Jev engine switch to a recon AI hook"
---

## When to Use

- Adding AI decision-making to an existing recon tool (tag selection, extension
  guessing, WAF classification, etc.).

For adding a whole new recon tool, use `recon-tool-integration`. For the setting
that toggles it, use `project-settings-cascade`.

---

## Critical Rules

- **NEVER let the AI helper raise.** Every failure path returns the user's
  current value. Recon stdout tails into the webapp's SSE recon drawer, so an
  exception both breaks the scan and blanks the stream. Pattern:
  [recon/helpers/ai_planner/nuclei_tags.py](../../recon/helpers/ai_planner/nuclei_tags.py)
  ("Never raises -- returns `current_tags` on any failure").
- **NEVER fall back to an empty list/string.** For tools where empty means "skip
  the work" (nuclei tags, ffuf extensions) that **silently turns detection off**.
  Fall back to the user's current value, not `[]`/`""`.
- **NEVER call the LLM with no signal.** Empty fingerprint -> return the current
  value; do not send an empty prompt.
- **ALWAYS take the `agent_llm` breaker AFTER the cache check, and honour it by
  returning the existing fallback.** The agent's `/llm/*` endpoints share one
  breaker: `gate = agent_llm_gate()` (from
  [recon/helpers/ai_planner/__init__.py](../../recon/helpers/ai_planner/__init__.py));
  when `not gate.allowed`, print "... Agent LLM paused (breaker open) - using the
  fallback." and return the user's current value WITHOUT a POST. After the POST
  call `gate.record(resp=resp)`; in the except branch call `gate.record(exc=e)`.
  The cache is checked first so a cached answer is still served while the breaker
  is open. This is the same never-raise/never-empty fallback as above — the
  breaker just skips the call that would fail anyway when the agent is down.
- **A hook with an LLM | Jev engine switch takes `engine: str = "llm"` and uses
  its OWN breaker.** `engine == "jev"` posts to `/jev/<hook>` (same request body,
  same response shape as `/llm/<hook>`, so the existing validator is reused),
  takes `agent_jev_gate()` and logs `[*][<Tool>-Jev]`. Never record a Jev outcome
  on `agent_llm`: that breaker marks 401/402/403 FATAL for the whole run, so a Jev
  auth or credit failure would silence every LLM hook. The Jev gate reads the
  agent's 503 `error_type` (no token, auth, no credit, forbidden are FATAL; rate
  limited carries `retry_after`; the rest are transient). A Jev failure uses the
  hook's static fallback: never re-route to the LLM, never return empty.
- **The engine field is the THIRD level, and the master switch must not touch
  it.** `aiInPipeline` forces each per-hook AI flag; the `{tool}AiUseJev` engine
  fields stay OUT of `apply_ai_pipeline_overrides`, are in `KEPT_WHEN_ABSENT`
  (`webapp/src/lib/project-preset-utils.ts`) so a preset apply does not reset
  them, and a switch-ON is refused server-side unless the project's
  `jevProviderId` names a Jev row (TypeSafe or OpenRouter) on the project OWNER's
  account (`validateJevEngineChange`, every write path, fail closed). Give a hook a
  Jev engine only when a wrong answer cannot drop a finding: the Nuclei
  false-positive filter deletes findings from target-controlled bytes and has no
  Jev engine.
- **A Jev-only hook (`{tool}Jev{Feature}`, no LLM twin) has TWO levels and
  starts in shadow.** Nothing upstream folds its flag into `aiInPipeline`, so
  EVERY call site, full and partial, tests `AI_IN_PIPELINE and <FLAG>` itself;
  never add it to the master fan-out in `TargetSection.tsx`. Build it on
  `recon/helpers/ai_planner/jev_shadow.py` (`jev_post` takes the `agent_jev`
  breaker; `ShadowRecorder` caps the per-decision lines at 50, prints one
  summary, and keeps the records in the recon JSON under `jev_shadow.<hook>`).
  `ROLLOUT = SHADOW` acts on the deterministic path; `ROLLOUT = ACT` acts on
  Jev's answer with the deterministic result as the fallback, and flipping a
  hook is a separate change. In `AI_HOOKS` it is `kind: 'enable'`, so a false flag
  reports `off`, not `llm`.
- **A per-item hook puts its items in the state and names them by index.**
  A hostname, URL, path, title or stderr line is target data even when recon
  extracted it: never quote it in a question, never print it in a log line (a
  hostname with "port...scan" in it moves the recon drawer's phase). Agent side,
  use `_ask_items`, which sends each request only its own items; `_ask` re-sends
  one state per chunk and a scan's items would exceed the request limit.
- **NEVER hook the AI separately in partial recon.** Most tools share one entry
  function (e.g. `run_vuln_scan` is called by both `main_recon_modules/` and
  `partial_recon_modules/`); hook it **once** and both paths inherit. `grep` the
  function name to confirm before you edit. The feature must work in the full
  pipeline AND partial recon.
- **NEVER touch [webapp/src/lib/recon-presets/presets/](../../webapp/src/lib/recon-presets/):**
  the `aiInPipeline` cascade (`apply_ai_pipeline_overrides`,
  in [recon/project_settings.py](../../recon/project_settings.py)) is the
  single source of truth for per-tool AI flags. Presets must not hard-code them;
  update the Zod schema instead.
- **ALWAYS add a registry entry for the new `Project` column** `{tool}Ai{Feature}`
  in [recon_settings/registry.yaml](../../recon_settings/registry.yaml), beside
  `ffufAiExtensions`, `nucleiAiTags`, `nucleiAiResponseFilter` and
  `wafAiClassifier`. A test walking `Prisma.ProjectScalarFieldEnum` fails until
  every column has one. An AI hook is an ordinary boolean toggle: `mcp:
  settable`, `traffic: none` (the hook itself sends no traffic; the tool it
  advises does), and a `meaning` that says which decision it moves from the
  operator to the model.
- **ALWAYS cache a per-target hook** keyed by tech fingerprint (Server,
  X-Powered-By, ...) so N targets behind one stack collapse to one LLM call
  ([ffuf_extensions.py](../../recon/helpers/ai_planner/ffuf_extensions.py)). A
  per-scan hook ([nuclei_tags.py](../../recon/helpers/ai_planner/nuclei_tags.py))
  runs once and needs no cache.
- **ALWAYS put the toggle in two places bound to the same field**
  `data.{tool}Ai{Feature}`: the master AI-in-Pipeline panel
  (the `aiInPipeline` block in [TargetSection.tsx](../../webapp/src/components/projects/ProjectForm/sections/TargetSection.tsx))
  and the tool's own section (e.g.
  [NucleiSection.tsx](../../webapp/src/components/projects/ProjectForm/sections/NucleiSection.tsx)).
  Read AND write the same field; **no copy-on-flip** (they stay in sync because
  they share the field).

---

## The pieces

| Piece | File | Note |
| --- | --- | --- |
| Helper | `recon/helpers/ai_planner/{tool}_{feature}.py` | POSTs to the agent; never raises; logs `[*][{Tool}-AI]` / `[!][{Tool}-AI]` to stdout |
| Agent endpoint | [agentic/api.py](../../agentic/api.py) (e.g. `/llm/nuclei-tags` at :641, `/llm/ffuf-extensions` at :543) | Pydantic model; returns 422 (bad body) / 503 (no key), never 500 |
| Setting | [recon/project_settings.py](../../recon/project_settings.py) `DEFAULT_SETTINGS` + `fetch_project_settings` + both branches of `apply_ai_pipeline_overrides` | see `project-settings-cascade` |
| Zod | [webapp/src/lib/recon-preset-schema.ts](../../webapp/src/lib/recon-preset-schema.ts) | so AI-generated presets see the field |
| UI | `TargetSection.tsx` + the tool's section | two toggles, one field |

## Commands

```bash
docker compose build agent && docker compose up -d agent   # the /llm endpoint lives in agentic/ (baked)
# recon/*.py is volume-mounted at spawn - no rebuild
# verify: a minimal POST returns 422/503, never 500; and a live scan logs
# [*][{Tool}-AI] in BOTH a full run and a partial recon run; stop the agent -> scan still completes.
```

## Resources

- [docs/readmes/coding_agent_prompts/PROMPT.ADD_AI_IN_RECON.md](../../docs/readmes/coding_agent_prompts/PROMPT.ADD_AI_IN_RECON.md) - full walkthrough, per-target vs per-scan, verify steps
- Related skills: `recon-tool-integration`, `project-settings-cascade`

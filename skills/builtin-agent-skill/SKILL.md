---
name: builtin-agent-skill
description: >
  Adding a built-in Agent Skill (an attack technique like ssrf, xxe, rce) that
  ships hardcoded in RedAmon: classified by the Intent Router, injected into the
  agent prompt, toggled per project, badged in the chat drawer. Ten layers
  across agentic and webapp, two of which fail with no error.
  Trigger: adding or editing a built-in attack skill; a new
  agentic/prompts/<skill_id>_prompts.py; editing agentic/prompts/classification.py,
  agentic/prompts/__init__.py build_builtin_skill_workflow,
  agentic/prompts/skill_parts.py, KNOWN_ATTACK_PATHS in agentic/state.py, or the
  webapp AttackSkillsSection / AIAssistantDrawer.
license: MIT
metadata:
  author: redamon
  version: "1.0.0"
  scope: [agentic, webapp]
  auto_invoke:
    - "Adding a built-in attack skill to the agent"
    - "Editing agent skill classification, phase injection, or the attack-skill UI"
---

## When to Use

- Adding a first-class attack technique the agent classifies and follows a workflow for.

For a user-uploadable workflow, use `add-community-skill`
instead. For a *tool* the agent calls, use `agentic-tool-integration`.
For per-skill tunable defaults, use `project-settings-cascade`.

---

## Critical Rules

- **ALWAYS add the skill id to `KNOWN_ATTACK_PATHS`** in
  [agentic/state.py](../../agentic/state.py). It is the Pydantic validator's
  allowlist; miss it and the classifier's output is **rejected at runtime** even
  though every other layer is wired.
- **NEVER skip layers 8 and 9** (the chat-drawer layers). They live in webapp and
  produce **no error** when forgotten: the skill classifies and badges, but the
  drawer tooltip and one-click example prompts are silently missing. Layer 8 =
  `BUILT_IN_SKILLS` in [attack-skills/available/route.ts](../../webapp/src/app/api/users/[id]/attack-skills/available/route.ts);
  Layer 9 = a `SESubGroup` in [suggestionData.ts](../../webapp/src/app/graph/components/AIAssistantDrawer/suggestionData.ts).
- **NEVER let classification keywords overlap an existing skill.** Every enabled
  built-in competes for the same user message; overlapping keywords (e.g. saying
  "SQL" in an SSRF section) make both skills mis-route. Disambiguate in the
  "Key distinction" line of the section in [classification.py](../../agentic/prompts/classification.py).
- **ALWAYS gate the workflow on the required tool** in the skill's branch of
  `_build_builtin_skill_workflow_parts()` ([agentic/prompts/__init__.py](../../agentic/prompts/__init__.py)),
  which the think node (`_inject_builtin_skill_workflow()`), fireteam members and
  LATS all reach through `build_builtin_skill_workflow()`:
  `and "<tool>" in allowed_tools`. Without the guard the agent gets instructions
  for a tool `TOOL_PHASE_MAP` blocks in that phase.
- **ALWAYS register the skill's static workflow parts** in
  [agentic/prompts/skill_parts.py](../../agentic/prompts/skill_parts.py) and append
  each one through `_seam.resolve_skill_part(skill_id, part_id, CONSTANT, kwargs)`
  (`kwargs` only where the site calls `.format`; a block built from operator data
  stays a plain append and is not registered). That seam is where an approved
  plugin override of the text applies; an unregistered skill silently never gets
  one. The unit gate enforces it: `test_skill_parts_registry.py` fails for a skill
  in `KNOWN_ATTACK_PATHS` without parts, and `test_skill_parts_seam.py::
  test_registry_matches_call_sites` fails for a block appended past the seam once
  the skill is in `SKILLS` (+ `REQUIRED_TOOL`) of
  `agentic/tests/tools/record_skill_golden.py`. Then re-record the golden fixture
  with the command in that file's docstring.
- **NEVER assume existing projects inherit the new skill.** `builtIn` is a strict
  has-key check; existing projects need a jsonb update to `attackSkillConfig`.
- **NEVER teach a second inbound port.** A person's Kali sandbox takes inbound
  connections from a target on one port only (their pool port, or 4444 through
  their own tunnel), and the payload settings block names it: no literal LPORT,
  no `http.server` on a sandbox port, no JNDI referral server on 1389/1099, no
  relay or `nc`/`socat` listener on a fixed port, no `ngrok`/`chisel` of the
  skill's own. `agentic/tests/test_prompts_reverse_ports.py` scans every prompt
  file for them.
- **ALWAYS add a registry entry for a per-skill tunable that became a `Project`
  column** in
  [recon_settings/registry.yaml](../../recon_settings/registry.yaml). A test
  walking `Prisma.ProjectScalarFieldEnum` fails until every column has one.
  Draft it with `python3 tooling/scripts/extract_recon_registry.py`, edit it,
  then `python3 recon_settings/build.py`.
  An attack-skill tunable is ordinary `mcp: settable` tuning now, bounded by its
  registry entry and gated at scan start by `roeForbiddenCategories`,
  `roeForbiddenTools` and `roeAllowDos` rather than by being unreachable. Give it
  `traffic: active` so it joins the queued-job fingerprint, and `roe_capped:
  true` if its unit is `rps`.
- **Pick the snake_case id once and use that exact literal in all 10 layers.**
  `grep -rn "<skill_id>" webapp/src agentic` must show it everywhere before you
  rebuild (an existing id like `cve_exploit` spans ~38 files).

---

## The ten layers (all required end to end)

| # | Layer | File |
| --- | --- | --- |
| 1 | Workflow prompt | `agentic/prompts/<skill_id>_prompts.py` |
| 2 | Package re-export + `__all__` | [agentic/prompts/__init__.py](../../agentic/prompts/__init__.py) |
| 3 | Phase injection branch | `_build_builtin_skill_workflow_parts()` (same file) |
| 4 | Classification + validator | [classification.py](../../agentic/prompts/classification.py) `_BUILTIN_SKILL_MAP` **and** `KNOWN_ATTACK_PATHS` in [state.py](../../agentic/state.py) |
| 5 | Settings default | `ATTACK_SKILL_CONFIG.builtIn` in [agentic/project_settings.py](../../agentic/project_settings.py) |
| 6 | Prisma default | `attackSkillConfig` JSON in [schema.prisma](../../webapp/prisma/schema.prisma) |
| 7 | UI toggle + badge | [AttackSkillsSection.tsx](../../webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx) + [phaseConfig.ts](../../webapp/src/app/graph/components/AIAssistantDrawer/phaseConfig.ts) |
| 8 | Drawer tooltip | [attack-skills/available/route.ts](../../webapp/src/app/api/users/[id]/attack-skills/available/route.ts) `BUILT_IN_SKILLS` |
| 9 | Drawer example prompts | [suggestionData.ts](../../webapp/src/app/graph/components/AIAssistantDrawer/suggestionData.ts) |
| 10 | Part registry (plugin `skill.text` overrides) | [skill_parts.py](../../agentic/prompts/skill_parts.py) + the golden recorder `agentic/tests/tools/record_skill_golden.py` |

## Commands

```bash
docker compose build agent && docker compose up -d agent   # agentic/ is baked
docker compose exec webapp npx prisma db push              # NEVER prisma migrate
# verify the id is wired everywhere before rebuild:
grep -rn "<skill_id>" webapp/src agentic
```

## Resources

- [docs/readmes/coding_agent_prompts/PROMPT.ADD_BUILTIN_AGENT_SKILL.md](../../docs/readmes/coding_agent_prompts/PROMPT.ADD_BUILTIN_AGENT_SKILL.md) - full per-layer walkthrough, tunable-design patterns, failure triage
- Related skills: `agentic-tool-integration`, `project-settings-cascade`, `add-community-skill`

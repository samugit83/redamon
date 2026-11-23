---
name: add-community-skill
description: >
  Adding a Community Agent Skill: a Markdown attack-workflow file that users
  import from the catalog, which then competes in the Intent Router and is
  injected into the agent's system prompt. No Python, no rebuild - but it must
  name only real tools and stay classifiable.
  Trigger: adding or editing a .md workflow under agentic/community-skills/;
  authoring an importable attack skill (not a hardcoded one); editing the
  community-skills catalog or its README.
license: MIT
metadata:
  author: redamon
  version: "1.0.0"
  scope: [agentic]
  auto_invoke:
    - "Adding a Community Agent Skill (importable .md attack workflow)"
---

## When to Use

- Shipping a battle-tested attack workflow as an importable `.md`, without
  hardcoding it into Python.

For a hardcoded, first-class skill (9-layer wiring, badge, per-project toggle),
use `builtin-agent-skill` instead. For a reference/theory doc rather than a
workflow, that is a Community Chat Skill (different flow).

---

## Critical Rules

- **NEVER invent tool names.** Every step must name a key of `TOOL_REGISTRY`
  ([agentic/prompts/tool_registry.py](../../agentic/prompts/tool_registry.py)):
  `query_graph`, `kali_shell`, `execute_curl`, `execute_code`,
  `execute_playwright`, `execute_nuclei`, `execute_hydra`, `execute_ffuf`, ...
  A step naming a non-existent tool is dead on arrival.
- **NEVER call a `kali_shell` CLI that is not installed AND documented.** The
  binary must be in [mcp/kali-sandbox/Dockerfile](../../mcp/kali-sandbox/Dockerfile)
  and named in the `kali_shell` description (the `kali_toolbox` MCP tool serves
  that text verbatim; an unlisted binary does not exist for MCP clients). Prefer a
  tool already installed. A new one is an agent-tool change:
  [PROMPT.ADD_AGENTIC_TOOL.md](../../docs/readmes/coding_agent_prompts/PROMPT.ADD_AGENTIC_TOOL.md)
  Type A (pinned install, description, stealth rule, smoke test). Every wordlist or
  file path a command uses must exist in the image too.
- **NEVER rebuild the agent for the `.md` alone.** `./agentic/community-skills` is
  volume-mounted **read-only** into the container
  (the agent's `./agentic/community-skills:/app/community-skills:ro` volume in
  [docker-compose.yml](../../docker-compose.yml)); the `GET /community-skills`
  endpoint auto-discovers by globbing the directory. Drop the file and it is live
  on the next call. (This is the exception to "agentic/ changes need a rebuild" -
  that applies to baked Python, not the mounted skills dirs.) A skill that needs a
  NEW kali CLI is not rebuild-free: rebuild the Kali image (`docker compose --profile tools
  build kali-sandbox`; running sandboxes move to it once their work ends) AND the agent.
- **NEVER write a description that overlaps a built-in skill.** Imported skills
  compete with built-ins in the Intent Router; a generic or overlapping opening
  paragraph means the classifier never selects it. Make the first paragraph and
  the description distinct. If the skill covers the same attack class as a
  built-in (`KNOWN_ATTACK_PATHS` in `agentic/state.py`), add a
  `vs. <builtin> (built-in)` line telling the user to disable that built-in on
  import.
- **Commands must be copy-pasteable** in fenced blocks - no pseudo-code. The
  markdown content is injected verbatim into the system prompt.
- **Remember it is per-user, not global.** Users import via Global Settings >
  Agent Skills; already-imported users do NOT auto-pick-up new skills (they
  re-import; duplicates are skipped by name). The same skip means an EDIT to a
  shipped skill never reaches existing importers: they must delete the old copy
  and re-import. Say so in the CHANGELOG.

---

## Commands

```bash
# No build. Drop the file and confirm discovery:
ls agentic/community-skills/            # your new <skill>.md lives here
# GET /community-skills globs this dir; the row lands in the Postgres UserAttackSkill
# table only after a user clicks "Import from Community".
```

If [agentic/community-skills/README.md](../../agentic/community-skills/README.md)
has a skills table, add a row (check the file first; do not invent structure).

## Resources

- [docs/readmes/coding_agent_prompts/PROMPT.ADD_COMMUNITY_AGENT_SKILL.md](../../docs/readmes/coding_agent_prompts/PROMPT.ADD_COMMUNITY_AGENT_SKILL.md) - full authoring flow, classification tips, troubleshooting
- Related skill: `builtin-agent-skill`

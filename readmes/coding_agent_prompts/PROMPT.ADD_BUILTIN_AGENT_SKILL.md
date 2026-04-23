# ADD A BUILT-IN AGENT SKILL

Add **[SKILL_ID]** (e.g. `ssrf`, `xxe`, `deserialization`) as a new **built-in Agent Skill** to RedAmon.

> **Scope**: this is the heaviest of the three skill systems. A built-in Agent Skill ships hardcoded with the product: it lives in Python, is classified automatically by the Intent Router, has its own workflow prompt injected into the agent's system prompt, declares per-skill tool requirements, shows up with a dedicated badge in the UI, and is toggleable per project. Use this flow **only** when the skill has deep tool integration and stable, production-grade content. For user-uploadable workflows, see [PROMPT.ADD_COMMUNITY_AGENT_SKILL.md](PROMPT.ADD_COMMUNITY_AGENT_SKILL.md). For on-demand reference docs, see [PROMPT.ADD_COMMUNITY_CHAT_SKILL.md](PROMPT.ADD_COMMUNITY_CHAT_SKILL.md).

---

## Architecture recap (read this first)

A built-in Agent Skill is wired through **7 layers**. Every new skill must touch ALL of them to work end to end.

| # | Layer | File | What it does |
|---|---|---|---|
| 1 | Workflow prompts | [agentic/prompts/<skill_id>_prompts.py](../../agentic/prompts/) | Multi-line Python string constants: the per-phase workflow the LLM follows |
| 2 | Package re-exports | [agentic/prompts/__init__.py](../../agentic/prompts/__init__.py) | `from .<skill>_prompts import ...` and add to `__all__` |
| 3 | Phase injection | [agentic/prompts/__init__.py `get_phase_tools()`](../../agentic/prompts/__init__.py) | `_inject_builtin_skill_workflow()` branch that appends the prompts when the skill is classified |
| 4 | Classification | [agentic/prompts/classification.py](../../agentic/prompts/classification.py) | Section text in `_BUILTIN_SKILL_MAP`, criteria in `_CLASSIFICATION_INSTRUCTIONS`, entry in the ordered skill-id lists, entry in `valid_types` |
| 5 | Project settings defaults | [agentic/project_settings.py](../../agentic/project_settings.py) | Entry under `ATTACK_SKILL_CONFIG.builtIn` + any per-skill tunables (e.g. `SQLI_LEVEL`) |
| 6 | Prisma schema default | [webapp/prisma/schema.prisma](../../webapp/prisma/schema.prisma) line ~681 (`attackSkillConfig`) | JSON default for the Project field |
| 7 | Frontend UI + badge | [AttackSkillsSection.tsx](../../webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx) + [phaseConfig.ts](../../webapp/src/app/graph/components/AIAssistantDrawer/phaseConfig.ts) | Per-project toggle card + classification badge color/label |

Classification key = the snake_case string used EVERYWHERE: `cve_exploit`, `sql_injection`, `xss`, etc. Pick it once in Phase 1 and use that exact literal across all 7 layers.

---

## Critical rules (READ BEFORE EDITING)

- **Rebuild the agent container after any change** in `agentic/`. The `agent` container bakes source into the Docker image. The canonical rebuild is: `docker compose build agent && docker compose up -d agent`. The `recon_orchestrator` is volume-mounted and hot-reloads, but `agent` is NOT.
- **Prisma schema changes use `db push`, not `migrate`.** After editing [webapp/prisma/schema.prisma](../../webapp/prisma/schema.prisma): `docker compose exec webapp npx prisma db push`. Do not invoke `prisma migrate`, this project uses push-based workflow.
- **Webapp in dev uses hot reload.** If the user is running `docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d webapp`, frontend edits apply live. In prod, `docker compose build webapp`.
- **Python imports must already exist in the agent image.** Adding a new `import` that is not in [agentic/requirements.txt](../../agentic/requirements.txt) or [agentic/Dockerfile](../../agentic/Dockerfile) will crash-loop the container. Built-in skill prompts are pure string constants, so this rarely bites, but double-check any helper imports.
- **Do not break existing skills.** Classification is a cascade: every enabled built-in competes for the same user message. Keywords and boundaries in your new skill's classification section MUST NOT overlap with existing skills (e.g. do not say "SQL" in an SSRF skill).
- **No em dashes in any text you write.** Use hyphens or rephrase. This is a user preference enforced across the project.

---

## Phase 0: Pre-flight

Confirm this skill does not already exist:

1. Search [agentic/prompts/](../../agentic/prompts/) for any `<skill_id>_prompts.py`. If found, STOP.
2. Check `_BUILTIN_SKILL_MAP` in [classification.py](../../agentic/prompts/classification.py) for an existing entry with the same ID.
3. Check [AttackSkillsSection.tsx `BUILT_IN_SKILLS`](../../webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx) around lines 36-73.
4. Consider whether this should be a Community Agent Skill or a Chat Skill instead (see the comparison in [redamon.wiki/Chat-Skills.md "Complete Skill System Comparison"](../../redamon.wiki/Chat-Skills.md)). Built-in is only justified when you need custom tool-routing hooks, per-skill Python logic (format strings, conditional fallbacks, execution-trace inspection), or first-class badge treatment in the UI.

If all checks pass, proceed.

---

## Phase 1: Design (no code yet)

Fill in this skill contract before writing code. Every downstream file depends on it.

```
Skill ID (snake_case):    <skill_id>           # e.g. ssrf
Display name:             <Human Name>         # e.g. Server-Side Request Forgery
Short badge label:        <5 CHARS MAX>        # e.g. SSRF
Default enabled?:         true | false         # default OFF for destructive skills (DoS, brute, phishing)
Required tools:           <tool names>         # must exist in TOOL_REGISTRY; see below
Required phase guard:     <tool> in allowed_tools   # the gate inside _inject_builtin_skill_workflow
RoE gate?:                <none | ROE_ALLOW_*>  # e.g. DoS requires ROE_ALLOW_DOS
Classification keywords:  <comma list>         # disjoint from existing skills
Tunable settings:         <list of keys>       # e.g. SSRF_TIMEOUT, SSRF_CLOUD_METADATA
Post-exploitation?:       yes | no             # DoS says no; most say yes
```

**Required tools**: list the `TOOL_REGISTRY` names the skill depends on. Check which tools exist in [agentic/prompts/tool_registry.py](../../agentic/prompts/tool_registry.py). Common ones: `query_graph`, `kali_shell`, `execute_curl`, `execute_code`, `execute_playwright`, `execute_nuclei`, `execute_hydra`, `metasploit_console`.

**Phase guard**: when the classifier picks this skill but the required tool is blocked by `TOOL_PHASE_MAP`, the workflow MUST NOT inject (the agent would get instructions for a tool it cannot call). See the existing guards in `_inject_builtin_skill_workflow()`:
- `cve_exploit` gates on `"metasploit_console" in allowed_tools`
- `sql_injection` gates on `"kali_shell" in allowed_tools`
- `xss` gates on `"execute_curl" in allowed_tools`
- `brute_force_credential_guess` gates on `"execute_hydra" in allowed_tools`

Pick the analogous one for your skill.

---

## Phase 2: Write the workflow prompts (Layer 1)

Create [agentic/prompts/<skill_id>_prompts.py](../../agentic/prompts/). Study the existing ones first to match the format, tone, and level of detail:

- Simple single-phase skill: [agentic/prompts/brute_force_credential_guess_prompts.py](../../agentic/prompts/brute_force_credential_guess_prompts.py) (one big `HYDRA_BRUTE_FORCE_TOOLS` block + `HYDRA_WORDLIST_GUIDANCE`)
- Rich multi-section skill with format-string injection: [agentic/prompts/sql_injection_prompts.py](../../agentic/prompts/sql_injection_prompts.py) (`SQLI_TOOLS` is a `.format()` template with `{sqli_level}`, `{sqli_risk}`, `{sqli_tamper_scripts}`)
- Conditional sub-sections: [agentic/prompts/xss_prompts.py](../../agentic/prompts/xss_prompts.py) (`XSS_BLIND_WORKFLOW` only injected when the blind-callback setting is on)

Required exports from the file (suffix conventions come from the existing skills, follow them):

```python
# agentic/prompts/<skill_id>_prompts.py

<SKILL_ID_UPPER>_TOOLS = """
## <Skill Name> Workflow

### Step 1: ...
...
### Step N: Reporting
...
"""

# Optional: split sub-sections for conditional injection
<SKILL_ID_UPPER>_PAYLOAD_REFERENCE = """..."""
<SKILL_ID_UPPER>_OOB_WORKFLOW = """..."""
```

**Content rules for the `_TOOLS` prompt:**

1. Start with a one-paragraph purpose line. Then numbered steps with explicit tool invocations (`execute_curl`, `kali_shell ...`, etc.).
2. Every step the LLM must take should name the tool it uses, the exact command shape, and what to look for in the output.
3. For project-tunable behavior, use `.format()` placeholders like `{your_setting_key}` and wire them in at layer 3.
4. Include a **When to transition phases** note at the end of the informational-phase steps so the LLM knows to call `action="request_phase_transition"`.
5. Include a **Reporting guidelines** section at the end listing the fields the final report should contain.
6. **Do NOT use em dashes.** Use hyphens or rephrase.
7. Keep it under ~600 lines per file. If you need more, split into sub-section constants.

---

## Phase 3: Re-export from the package (Layer 2)

Edit [agentic/prompts/__init__.py](../../agentic/prompts/__init__.py).

**3.1** Add a new re-export block alongside the existing ones around lines 39-82:

```python
# Re-export from <Skill Name> prompts
from .<skill_id>_prompts import (
    <SKILL_ID_UPPER>_TOOLS,
    <SKILL_ID_UPPER>_PAYLOAD_REFERENCE,  # if you split sub-sections
    # ...
)
```

**3.2** Add each constant name to the `__all__` list at the bottom of the file (around lines 364-422). Follow the existing grouping pattern (one `# Skill Name` comment then the constants).

---

## Phase 4: Wire the workflow into phase injection (Layer 3)

Edit `_inject_builtin_skill_workflow()` inside [agentic/prompts/__init__.py](../../agentic/prompts/__init__.py) (lines ~213-304).

Add a new `elif` branch. Model it on the existing skill closest to yours:

```python
elif (attack_path_type == "<skill_id>"
        and "<skill_id>" in enabled_builtins
        and "<required_tool>" in allowed_tools
        # Optional: RoE gate
        and not (get_setting('ROE_ENABLED', False) and not get_setting('ROE_ALLOW_<X>', False))
        ):
    # If your prompt uses format placeholders, resolve them from settings here:
    <skill>_settings = {
        'your_setting': get_setting('YOUR_SETTING_KEY', <default>),
        # ...
    }
    parts.append(<SKILL_ID_UPPER>_TOOLS.format(**<skill>_settings))
    # Optional conditional sub-sections:
    if <skill>_settings['your_setting'] and "<other_tool>" in allowed_tools:
        parts.append(<SKILL_ID_UPPER>_OOB_WORKFLOW)
    parts.append(<SKILL_ID_UPPER>_PAYLOAD_REFERENCE)
    return True
```

**Ordering matters.** Place your branch before the `cve_exploit` branch if it should take precedence when CVE keywords overlap (e.g. an auth-bypass skill); otherwise keep it alphabetical with the other skills.

**If your skill needs post-exploitation guidance**, the `post_exploitation` branch (lines ~342-358) currently only special-cases user skills and the Metasploit post-expl prompts. If your skill needs a custom post-expl prompt, add a branch there too. Most skills reuse the generic Metasploit post-expl when `metasploit_console` is allowed.

---

## Phase 5: Classification (Layer 4)

Edit [agentic/prompts/classification.py](../../agentic/prompts/classification.py).

**5.1** Add a section constant near lines 16-71:

```python
_<SKILL_ID_UPPER>_SECTION = """### <skill_id> - <Display Name>
- <one-line description>
- <bullet listing what the skill covers>
- Key distinction: <how this differs from neighboring skills (SQLi / XSS / unclassified)>
- Keywords: <comma-separated list>
"""
```

Keyword list guidance: pick terms the user is likely to type. Keep them disjoint from existing sections. If there is overlap (e.g. both SQLi and XSS can say "WAF bypass"), disambiguate in the "Key distinction" line.

**5.2** Add your skill to `_BUILTIN_SKILL_MAP` (lines 74-81). Pick a unique priority letter (the letter is informational, keep alphabetical order by letter):

```python
_BUILTIN_SKILL_MAP = {
    'phishing_social_engineering': (_PHISHING_SECTION, 'a', 'phishing_social_engineering'),
    'brute_force_credential_guess': (_BRUTE_FORCE_SECTION, 'b', 'brute_force_credential_guess'),
    'cve_exploit': (_CVE_EXPLOIT_SECTION, 'c', 'cve_exploit'),
    'denial_of_service': (_DOS_SECTION, 'd', 'denial_of_service'),
    'sql_injection': (_SQLI_SECTION, 'e', 'sql_injection'),
    'xss': (_XSS_SECTION, 'f', 'xss'),
    '<skill_id>': (_<SKILL_ID_UPPER>_SECTION, 'g', '<skill_id>'),   # <-- new
}
```

**5.3** Add your entry to `_CLASSIFICATION_INSTRUCTIONS` (lines 84-108):

```python
'<skill_id>': """   - **<skill_id>**:
      - <targeted yes/no classification questions, usually 3-4 bullets>""",
```

**5.4** Add your skill ID to BOTH ordered lists in `build_classification_prompt()`:

- Line ~171: the list used to render sections in order
- Line ~202 (`builtin_skill_ids`): the list used to render classification criteria

```python
for skill_id in ['phishing_social_engineering', 'brute_force_credential_guess',
                 'cve_exploit', 'denial_of_service', 'sql_injection', 'xss',
                 '<skill_id>']:  # <-- add here AND in builtin_skill_ids below
```

**5.5** (Optional, usually skip) If the skill must be excluded when RoE forbids it (like `denial_of_service` is gated on `ROE_ALLOW_DOS`), add a corresponding `enabled_builtins.discard('<skill_id>')` block around lines 119-126.

**5.6** (Optional, only if renaming defaults) The line at ~218 picks the default classification when the request is vague. Leave it as `cve_exploit`.

---

## Phase 6: Project settings defaults (Layer 5)

Edit [agentic/project_settings.py](../../agentic/project_settings.py).

**6.1** Add the skill ID to `ATTACK_SKILL_CONFIG.builtIn` (lines 189-200):

```python
'ATTACK_SKILL_CONFIG': {
    'builtIn': {
        'cve_exploit': True,
        'brute_force_credential_guess': False,
        'phishing_social_engineering': False,
        'denial_of_service': False,
        'sql_injection': True,
        'xss': True,
        '<skill_id>': <True_or_False>,    # <-- new
    },
    'user': {},
},
```

Default to `True` only for non-destructive, widely-useful skills. Default `False` anything that is invasive, noisy, or has legal/RoE implications.

**6.2** Add any per-skill tunables to `DEFAULT_AGENT_SETTINGS`. Follow the naming pattern of existing skills:

- SQLi uses `SQLI_LEVEL`, `SQLI_RISK`, `SQLI_TAMPER_SCRIPTS` (lines 180-182)
- XSS uses `XSS_DALFOX_ENABLED`, `XSS_BLIND_CALLBACK_ENABLED`, `XSS_CSP_BYPASS_ENABLED` (lines 185-187)

Example:

```python
# <Skill Name> Testing
'<SKILL_ID_UPPER>_<SETTING>': <default>,
```

These keys are what you read in `_inject_builtin_skill_workflow()` via `get_setting(...)` in Phase 4.

---

## Phase 7: Prisma schema default (Layer 6)

Edit [webapp/prisma/schema.prisma](../../webapp/prisma/schema.prisma) at line ~681. The `attackSkillConfig` field has a hardcoded JSON default:

```prisma
attackSkillConfig    Json     @default("{\"builtIn\":{\"cve_exploit\":true,\"brute_force_credential_guess\":true,\"phishing_social_engineering\":true,\"denial_of_service\":true,\"sql_injection\":true,\"xss\":true},\"user\":{}}") @map("attack_skill_config")
```

Add your skill ID to the JSON. Keep the escaping intact (note `\"`):

```prisma
attackSkillConfig    Json     @default("{\"builtIn\":{\"cve_exploit\":true,...,\"xss\":true,\"<skill_id>\":<true_or_false>},\"user\":{}}") @map("attack_skill_config")
```

Then run:

```bash
docker compose exec webapp npx prisma db push
```

Existing projects have their own stored `attackSkillConfig` JSON and will NOT auto-pick up the new key (missing keys are treated as "enabled" by the `user` side of `get_enabled_user_skills`, but `builtIn` is a strict has-key check in `get_enabled_builtin_skills`). If you want existing rows to inherit the default, run:

```bash
docker compose exec webapp npx prisma db execute --stdin <<'SQL'
UPDATE projects
SET attack_skill_config = jsonb_set(
  attack_skill_config::jsonb,
  '{builtIn,<skill_id>}',
  '<true_or_false>'::jsonb,
  true
);
SQL
```

Ask the user first before running this; it mutates every project in the DB.

---

## Phase 8: Frontend UI + badge (Layer 7)

**8.1** Edit [webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx](../../webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx).

Add an entry to the `BUILT_IN_SKILLS` array at lines 36-73. Pick an icon from `lucide-react` (the file already imports `Bug`, `KeyRound`, `Mail`, `Swords`, `Settings`, `Zap`, `Database`, `Code2` at line 5, add more as needed):

```tsx
{
  id: '<skill_id>',
  name: '<Display Name>',
  description: '<one-line description of what the skill does>',
  icon: <YourIcon size={16} />,
},
```

Add the same key to `DEFAULT_CONFIG.builtIn` at lines 80-90 (must match Phase 6 exactly).

If the skill has tunable settings that need their own sub-section UI (like `SqliSection.tsx`, `DosSection.tsx`, `HydraSection.tsx`, `PhishingSection.tsx`), create a new sibling component and conditionally render it inside the main `AttackSkillsSection` where the other sub-sections are rendered (around lines 225-236 in the file). If your skill only has simple boolean/number settings, skip this.

**8.2** Edit [webapp/src/app/graph/components/AIAssistantDrawer/phaseConfig.ts](../../webapp/src/app/graph/components/AIAssistantDrawer/phaseConfig.ts).

Add a classification badge config inside `KNOWN_ATTACK_PATH_CONFIG` at lines 51-88. Pick a color that is visually distinct from the existing 6:

```tsx
<skill_id>: {
  label: '<Display Name>',
  shortLabel: '<5 CHARS MAX>',
  color: 'var(--<css-var>, #<hex>)',
  bgColor: 'rgba(<r>, <g>, <b>, 0.15)',
},
```

Existing colors in use:
- warning (amber) `cve_exploit`
- purple (#8b5cf6) `brute_force_credential_guess`
- pink (#ec4899) `phishing_social_engineering`
- red (#ef4444) `denial_of_service`
- cyan (#06b6d4) `sql_injection`
- green (#10b981) `xss`
- blue (#3b82f6) reserved for user skills
- gray reserved for unclassified

---

## Phase 9: Rebuild and verify

```bash
# 1. Rebuild the agent container (MANDATORY for any agentic/ change)
docker compose build agent && docker compose up -d agent

# 2. Push the Prisma schema
docker compose exec webapp npx prisma db push

# 3. Rebuild webapp (skip if running in dev mode with hot reload)
docker compose build webapp && docker compose up -d webapp
```

### Smoke test

1. Open the webapp, create a fresh project. Go to Project Settings > Agent Skills. Confirm the new skill card appears with the right icon, name, and description, and the toggle reflects the default state from Phase 6/7.
2. Toggle the skill ON. Save the project.
3. Open the AI Assistant drawer, send a message that clearly matches the skill's keywords (from Phase 5.1). Watch the classification badge above the input:
   - With the skill ON: the badge should show your new `shortLabel` with your color.
   - Toggle it OFF and resend: the badge should fall back to `<term>-unclassified` (gray).
4. Check the agent logs (`docker compose logs -f agent`) and look for the workflow prompt being included in the system prompt at the start of the ReAct loop. Grep for your `<SKILL_ID_UPPER>_TOOLS` marker text.
5. If your skill has a phase guard (Phase 4), test it: disable the required tool in Project Settings > Tool Phase Restrictions and confirm the workflow is NOT injected (the agent should fall back to `UNCLASSIFIED_EXPLOIT_TOOLS`).
6. If you added RoE gating (Phase 5.5), enable RoE without the permission and confirm the skill is excluded from classification.

### Failure triage

| Symptom | Likely cause |
|---|---|
| Agent container crash-loops after build | Import error in `<skill_id>_prompts.py` or `__init__.py`; check `docker compose logs agent` |
| Badge always shows `SKILL` (blue) | You wired as user skill by mistake; classifier returning `user_skill:<id>` |
| Badge always shows unclassified (gray) | Classification not wired. Check `_BUILTIN_SKILL_MAP` + both ordered lists + `_CLASSIFICATION_INSTRUCTIONS` all have the skill |
| Toggle on UI does not persist | `DEFAULT_CONFIG` in [AttackSkillsSection.tsx](../../webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx) and the Prisma JSON default drifted; make them match |
| Workflow prompt missing in agent logs | Phase guard failing: required tool not in `allowed_tools`; check `TOOL_PHASE_MAP` for the tool and phase |
| `KeyError` on `get_setting` | You referenced a setting in `_inject_builtin_skill_workflow()` that you forgot to add to `DEFAULT_AGENT_SETTINGS` |

---

## Quick checklist

- [ ] `agentic/prompts/<skill_id>_prompts.py` created with `<SKILL_ID_UPPER>_TOOLS`
- [ ] Constants re-exported in [agentic/prompts/__init__.py](../../agentic/prompts/__init__.py) + added to `__all__`
- [ ] New `elif` branch in `_inject_builtin_skill_workflow()` with phase guard
- [ ] `_<SKILL_ID_UPPER>_SECTION` added and wired into `_BUILTIN_SKILL_MAP`
- [ ] `_CLASSIFICATION_INSTRUCTIONS[<skill_id>]` added
- [ ] `<skill_id>` added to BOTH ordered lists in `build_classification_prompt()`
- [ ] `ATTACK_SKILL_CONFIG.builtIn.<skill_id>` default added in [project_settings.py](../../agentic/project_settings.py)
- [ ] Per-skill tunables (if any) added to `DEFAULT_AGENT_SETTINGS`
- [ ] [Prisma schema](../../webapp/prisma/schema.prisma) `attackSkillConfig` default JSON updated + `prisma db push`
- [ ] `BUILT_IN_SKILLS` entry added in [AttackSkillsSection.tsx](../../webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx)
- [ ] `DEFAULT_CONFIG.builtIn.<skill_id>` added in [AttackSkillsSection.tsx](../../webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx)
- [ ] `KNOWN_ATTACK_PATH_CONFIG[<skill_id>]` badge added in [phaseConfig.ts](../../webapp/src/app/graph/components/AIAssistantDrawer/phaseConfig.ts)
- [ ] Agent container rebuilt; webapp rebuilt (or hot-reloaded in dev)
- [ ] End-to-end smoke test passed (keyword -> badge -> workflow in system prompt)

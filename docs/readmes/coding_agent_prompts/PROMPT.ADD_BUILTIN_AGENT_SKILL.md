# ADD A BUILT-IN AGENT SKILL

Add **[SKILL_ID]** (e.g. `ssrf`, `xxe`, `deserialization`) as a new **built-in Agent Skill** to RedAmon.

> **Scope**: this is the heaviest of the three skill systems. A built-in Agent Skill ships hardcoded with the product: it lives in Python, is classified automatically by the Intent Router, has its own workflow prompt injected into the agent's system prompt, declares per-skill tool requirements, shows up with a dedicated badge in the UI, and is toggleable per project. Use this flow **only** when the skill has deep tool integration and stable, production-grade content. For user-uploadable workflows, see [PROMPT.ADD_COMMUNITY_AGENT_SKILL.md](PROMPT.ADD_COMMUNITY_AGENT_SKILL.md). For on-demand reference docs, see [PROMPT.ADD_COMMUNITY_CHAT_SKILL.md](PROMPT.ADD_COMMUNITY_CHAT_SKILL.md).

---

## Architecture recap (read this first)

A built-in Agent Skill is wired through **10 layers** (the same ten as the [`builtin-agent-skill`](../../../skills/builtin-agent-skill/SKILL.md) skill). Every new skill must touch ALL of them to work end to end. Layers 8 and 9 are the ones implementers most often forget -- they are not in the project-settings page, they live in the chat drawer, and missing them produces silent UX gaps (no tooltip entry, no example prompts) without any error. Layer 10 is silent at runtime too: an unregistered skill renders normally and simply never receives an approved plugin override of its text; the unit gate is what catches it.

| # | Layer | File | What it does |
|---|---|---|---|
| 1 | Workflow prompts | [agentic/prompts/<skill_id>_prompts.py](../../../agentic/prompts/) | Multi-line Python string constants: the per-phase workflow the LLM follows |
| 2 | Package re-exports | [agentic/prompts/__init__.py](../../../agentic/prompts/__init__.py) | `from .<skill>_prompts import ...` and add to `__all__` |
| 3 | Phase injection | [agentic/prompts/__init__.py `_build_builtin_skill_workflow_parts()`](../../../agentic/prompts/__init__.py) | A branch that, when the skill is classified, enabled and its tool allowed, appends each prompt part through `_seam.resolve_skill_part(...)` and returns `parts`. The think node (`_inject_builtin_skill_workflow()` inside `get_phase_tools()`, a thin wrapper), Fireteam members and LATS all reach it through `build_builtin_skill_workflow()` |
| 4 | Classification | [agentic/prompts/classification.py](../../../agentic/prompts/classification.py) + [agentic/state.py](../../../agentic/state.py) `KNOWN_ATTACK_PATHS` | Section text in `_BUILTIN_SKILL_MAP`, criteria in `_CLASSIFICATION_INSTRUCTIONS`, entry in the ordered skill-id lists, entry in `valid_types`, AND add the skill ID to `KNOWN_ATTACK_PATHS` so the Pydantic validator accepts the classifier output |
| 5 | Project settings defaults | [agentic/project_settings.py](../../../agentic/project_settings.py) | Entry under `ATTACK_SKILL_CONFIG.builtIn` + any per-skill tunables (e.g. `SQLI_LEVEL`) + `fetch_agent_settings` mappings if the tunables are per-project |
| 6 | Prisma schema default | [webapp/prisma/schema.prisma](../../../webapp/prisma/schema.prisma) (`attackSkillConfig` on `Project`) | JSON default for the Project field, plus any per-skill columns if you added Prisma-backed tunables |
| 6b | **Settings registry** | [recon_settings/registry.yaml](../../../recon_settings/registry.yaml) | Only if Layer 6 added `Project` columns. Describe each one and run `python3 recon_settings/build.py`; the build FAILS on an undescribed column, so this layer announces itself. **`mcp: settable` is the normal answer** — see the checklist item below for why, and for the two things that actually control a per-skill tunable. |
| 7 | Frontend UI + badge | [AttackSkillsSection.tsx](../../../webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx) + [phaseConfig.ts](../../../webapp/src/app/graph/components/AIAssistantDrawer/phaseConfig.ts) | Per-project toggle card + classification badge color/label |
| 8 | **Drawer skills tooltip API** | [webapp/src/app/api/users/[id]/attack-skills/available/route.ts](../../../webapp/src/app/api/users/[id]/attack-skills/available/route.ts) `BUILT_IN_SKILLS` array | Drives the **Agent Skills tooltip** in the chat-drawer header (the hover panel on the active-skill badge). Skills missing from this hardcoded list will not appear in the tooltip even if classification picks them. |
| 9 | **Drawer suggestion prompts** | [webapp/src/app/graph/components/AIAssistantDrawer/suggestionData.ts](../../../webapp/src/app/graph/components/AIAssistantDrawer/suggestionData.ts) `EXPLOITATION_GROUPS` (and `INFORMATIONAL_GROUPS` / `POST_EXPLOITATION_GROUPS` if applicable) | Example-prompt cards in the chat-drawer suggestion dropdown. Add a new `SESubGroup` block with the skill's `id`, a human title, and 4-6 ready-to-send prompt examples that exercise the skill. Without this entry the user has no one-click way to invoke the new skill. |
| 10 | **Part registry** (plugin `skill.text` overrides) | [agentic/prompts/skill_parts.py](../../../agentic/prompts/skill_parts.py) `_SPECS` + the golden recorder [agentic/tests/tools/record_skill_golden.py](../../../agentic/tests/tools/record_skill_golden.py) | One entry per static part the branch appends, in assembly order. `_seam.resolve_skill_part` is where an approved plugin override of a part applies, and it applies only to a registered part. `test_skill_parts_registry.py` fails for a skill in `KNOWN_ATTACK_PATHS` without parts; `test_skill_parts_seam.py::test_registry_matches_call_sites` fails for a block appended past the seam once the skill is in `SKILLS` (+ `REQUIRED_TOOL`) of the recorder. |

Classification key = the snake_case string used EVERYWHERE: `cve_exploit`, `sql_injection`, `xss`, etc. Pick it once in Phase 1 and use that exact literal across all 10 layers.

> **Two more sites that behave like silent layers (add them for first-class parity).** Neither errors if forgotten, but the skill is degraded without them:
> - **`build_skill_menu()` `order` list** in [classification.py](../../../agentic/prompts/classification.py) — the per-turn "re-evaluate skill EVERY turn" menu that drives mid-run `switch_skill`. It has its OWN ordered list separate from the two in `build_classification_prompt()`; if your id is missing here, the agent sees the class name as switchable but never its section/criteria each turn, so it will not switch to it from live evidence.
> - **`build_attack_path_behavior()`** in [base.py](../../../agentic/prompts/base.py) — a per-skill behavior blurb (informational vs exploitation). Miss it and the skill falls through to a generic one-line fallback instead of the specific steering every other first-class skill gets.

A handful of files reference skill IDs only in doc-comments. These do NOT affect runtime, but updating them along with the new skill prevents future readers from being misled. `grep -rn "cve_exploit" webapp/src/` will surface every remaining reference.

---

## Critical rules (READ BEFORE EDITING)

- **Rebuild the agent container after any change** in `agentic/`. The `agent` container bakes source into the Docker image. The canonical rebuild is: `docker compose build agent && docker compose up -d agent`. The `recon_orchestrator` is volume-mounted and hot-reloads, but `agent` is NOT.
- **Prisma schema changes use `db push`, not `migrate`.** After editing [webapp/prisma/schema.prisma](../../../webapp/prisma/schema.prisma): `docker compose exec webapp npx prisma db push`. Do not invoke `prisma migrate`, this project uses push-based workflow.
- **Webapp in dev uses hot reload.** If the user is running `docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d webapp`, frontend edits apply live. In prod, `docker compose build webapp`.
- **Python imports must already exist in the agent image.** Adding a new `import` that is not in [agentic/requirements.txt](../../../agentic/requirements.txt) or [agentic/Dockerfile](../../../agentic/Dockerfile) will crash-loop the container. Built-in skill prompts are pure string constants, so this rarely bites, but double-check any helper imports.
- **Do not break existing skills.** Classification is a cascade: every enabled built-in competes for the same user message. Keywords and boundaries in your new skill's classification section MUST NOT overlap with existing skills (e.g. do not say "SQL" in an SSRF skill).
- **No em dashes in any text you write.** Use hyphens or rephrase. This is a user preference enforced across the project.

---

## Phase 0: Pre-flight

Confirm this skill does not already exist:

1. Search [agentic/prompts/](../../../agentic/prompts/) for any `<skill_id>_prompts.py`. If found, STOP.
2. Check `_BUILTIN_SKILL_MAP` in [classification.py](../../../agentic/prompts/classification.py) for an existing entry with the same ID.
3. Check [AttackSkillsSection.tsx `BUILT_IN_SKILLS`](../../../webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx).
4. Consider whether this should be a Community Agent Skill or a Chat Skill instead (see the comparison in [redamon.wiki/Chat-Skills.md "Complete Skill System Comparison"](../../../redamon.wiki/Chat-Skills.md)). Built-in is only justified when you need custom tool-routing hooks, per-skill Python logic (format strings, conditional fallbacks, execution-trace inspection), or first-class badge treatment in the UI.

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
Required phase guard:     <tool> in allowed_tools   # the gate on the skill's branch in _build_builtin_skill_workflow_parts
RoE gate?:                <none | ROE_ALLOW_*>  # e.g. DoS requires ROE_ALLOW_DOS
Classification keywords:  <comma list>         # disjoint from existing skills
Tunable settings:         <list of keys>       # e.g. SSRF_TIMEOUT, SSRF_CLOUD_METADATA
Post-exploitation?:       yes | no             # DoS says no; most say yes
```

**Required tools**: list the `TOOL_REGISTRY` names the skill depends on. Check which tools exist in [agentic/prompts/tool_registry.py](../../../agentic/prompts/tool_registry.py). Common ones: `query_graph`, `kali_shell`, `execute_curl`, `execute_code`, `execute_playwright`, `execute_nuclei`, `execute_hydra`, `metasploit_console`.

**Phase guard**: when the classifier picks this skill but the required tool is blocked by `TOOL_PHASE_MAP`, the workflow MUST NOT inject (the agent would get instructions for a tool it cannot call). See the existing guards in `_build_builtin_skill_workflow_parts()`:
- `cve_exploit` gates on `"metasploit_console" in allowed_tools`
- `sql_injection` gates on `"kali_shell" in allowed_tools`
- `xss` gates on `"execute_curl" in allowed_tools`
- `brute_force_credential_guess` gates on `"execute_hydra" in allowed_tools`

Pick the analogous one for your skill.

---

## Phase 1.5: Designing tunables (decide BEFORE you write the prompt)

The "Tunable settings" line in the Phase 1 contract is the most consequential design choice in the whole skill. Every tunable becomes: a default in `DEFAULT_AGENT_SETTINGS`, a column in the Prisma `Project` model, a field mapping in `fetch_agent_settings`, a UI control in the per-skill section component, and a value read in the skill's branch of `_build_builtin_skill_workflow_parts`. Wrong calls here ripple across every layer below; right calls let the prompt and sub-prompts vary per-engagement without touching code.

### When to add a tunable (the decision rule)

Add a tunable ONLY when the answer is yes to at least one of the following, AND no to the disqualifier:

- **Operator-meaningful?** Would a real pentester or compliance officer change this between engagements? (e.g. "client forbids OOB callbacks", "client wants only AWS metadata pivots", "engagement permits aggressive payloads").
- **Site-specific?** Does the value depend on the target environment, not the technique? (e.g. internal CIDR ranges, custom internal hostnames, OOB provider domain when oast.fun is blocked).
- **Scope-altering?** Does the value flip whether a meaningful sub-workflow ships in the prompt at all? (e.g. SSRF cloud-metadata sub-section, RCE deserialization sub-section, XSS blind-callback workflow).
- **RoE-sensitive?** Does the value gate behaviour that an RoE document would explicitly forbid? (e.g. data exfiltration, account lockout, persistent footholds, container escape).
- **Prompt-bloat gate?** Does the value let a small client trim a 5+ KB sub-section the LLM doesn't always need? (e.g. SSRF advanced payload reference, XSS CSP-bypass guidance).

**Disqualifier (do NOT make it a tunable):** the agent can decide this at runtime from observed target behaviour. Concretely: which payload to try first, whether to escalate to a noisier technique, retry counts, timing variance for oracle detection, which order to enumerate parameters in, how many parallel curls to fire. These belong in the prompt as guidance ("start with the simplest payload; escalate only if filtered"), not in settings.

A useful sanity-check: count the per-skill knobs an upstream prompt actually parameterizes. Strix prompts have ~0-2 user-facing variables; Shannon has ~5-10 because of the deliverable-CLI plumbing we strip. Aim for 2-5 RedAmon tunables; over 6 usually means something belongs in code as the agent's default.

### The three dynamic-prompt patterns (and when to use each)

Pick the pattern based on what the setting actually changes:

#### Pattern A: String `.format()` placeholder

The setting value flows directly into the rendered prompt text. Use when the agent needs to SEE the value to act on it (a numeric threshold, a free-text scope hint, a pre-resolved CLI flag string).

- Source: [agentic/prompts/sql_injection_prompts.py](../../../agentic/prompts/sql_injection_prompts.py) `SQLI_TOOLS` uses `{sqli_level}`, `{sqli_risk}`, `{sqli_tamper_scripts}`.
- Wiring (Layer 3): pass the settings dict as the last argument of `_seam.resolve_skill_part(skill_id, "tools", <SKILL>_TOOLS, settings_dict)`, which calls `.format(**settings_dict)`. Layer 10 registers that part as `TEMPLATE` with exactly those placeholder names.
- Best for: thresholds (`SQLI_LEVEL=3`), pre-built flag strings (`HYDRA_FLAGS`), free-text site context (`SSRF_CUSTOM_INTERNAL_TARGETS`), hostname / CIDR lists, OOB provider domain.
- Caveat: the prompt MUST escape literal braces (`{{` / `}}`) everywhere else in the template; Python's `str.format` will otherwise raise `KeyError`. Run a unit test that calls `.format(**defaults)` to catch this on every prompt change.

#### Pattern B: Whole sub-section conditional injection

An entire pre-rendered markdown block is appended to `parts` only when a boolean is True. Use when the alternative is "the agent doesn't need this content at all in this engagement."

- Source: [agentic/prompts/xss_prompts.py](../../../agentic/prompts/xss_prompts.py) `XSS_BLIND_WORKFLOW` is appended only when `XSS_BLIND_CALLBACK_ENABLED` is True.
- Wiring (Layer 3): `if setting and "tool" in allowed_tools: parts.append(_seam.resolve_skill_part(skill_id, "<part_id>", SUB_SECTION))` after the main part, with no format arguments. Layer 10 registers it as `PLAIN`, with the condition as its gate.
- Best for: heavy reference blocks (3-10 KB) that only some engagements need, OOB callback workflows, optional payload reference tables, language-specific deserialization workflows, cloud-provider-specific blocks.
- Caveat: the sub-section constant is appended raw, NOT formatted. So it uses single braces `{...}` for legitimate JSON / Jinja2 / IFS / etc. If you accidentally write `{{...}}` thinking it will be substituted, it will reach the LLM with literal double braces. A regex check `re.findall(r'\{rce_[a-z_]+\}', SUB_SECTION) == []` prevents misuse-of-format-placeholder leaks.

#### Pattern C: Swap-block (one-of-N substitution into a `.format` slot)

A `{block_name}` placeholder in the main template is filled with one of two (or more) prebuilt strings, picked by the setting. Use when the alternative is not "skip" but "behave differently."

- Source A: [agentic/prompts/denial_of_service_prompts.py](../../../agentic/prompts/denial_of_service_prompts.py) `DOS_TOOLS` has a `{dos_assessment_only_block}` slot filled with either an inline assessment-mode warning or empty string.
- Source B: [agentic/prompts/rce_prompts.py](../../../agentic/prompts/rce_prompts.py) `RCE_TOOLS` has a `{rce_aggressive_block}` slot filled with `RCE_AGGRESSIVE_DISABLED` (forbids destructive techniques) or `RCE_AGGRESSIVE_ENABLED` (permits them with mandatory cleanup).
- Wiring (Layer 3): resolve the swap value first and pass it as a placeholder value: `parts.append(_seam.resolve_skill_part(skill_id, "tools", MAIN_TOOLS, {..., "my_block": BLOCK_A if cond else BLOCK_B}))`. The swap-in blocks are values, not registered parts, so no plugin override replaces them (as with the RCE aggressive blocks).
- Best for: assessment-vs-active modes, aggressive-vs-conservative payload sets, stealth-vs-loud guidance, RoE-gated step replacements.
- Caveat: the swap-in strings are themselves NOT format-templated (Python's `str.format` does not recurse into substituted values). So they use single braces `{...}` for any legit content. Same brace discipline as Pattern B.

### Picking defaults

Apply this matrix when assigning the boolean default in `DEFAULT_AGENT_SETTINGS`:

| Behaviour the setting enables | Default | Reason |
|-------------------------------|---------|--------|
| Sends data outside the engagement (OOB, blind callback, exfil to oast.fun) | `False` | Some clients ban external infrastructure even for testing. Operator must opt in. |
| Modifies target state (file write, persistent shell, account changes, cron) | `False` | Cleanup obligation, audit trail, RoE risk. |
| Probes cloud metadata or container/k8s APIs | `True` (with sub-section toggle off if you want trimmed prompts) | Common in cloud engagements; passive reads. |
| Adds payload reference / WAF-bypass / CSP-bypass guidance | `True` | Pure prompt content, no target side-effect. Lets less-experienced agents pick the right payload. |
| Selects between conservative and aggressive payload sets | `False` (conservative) | Read-only proofs already satisfy a Level 3 finding for most skills. |
| Trims a heavy sub-section purely for prompt length | `True` (include) | Default to full coverage; let length-conscious operators turn off. |

If a setting is RoE-gated (e.g. `denial_of_service` requires `ROE_ALLOW_DOS`), default the FEATURE flag to True (so the prompt is functional when RoE permits) and let the RoE gate in classification + injection do the actual blocking. Do not double-gate.

### Naming + storage conventions

- **Setting key:** `<SKILL_ID_UPPER>_<FEATURE>_ENABLED` for booleans, `<SKILL_ID_UPPER>_<NOUN>` for values. Examples: `SSRF_OOB_CALLBACK_ENABLED`, `SSRF_REQUEST_TIMEOUT`, `RCE_AGGRESSIVE_PAYLOADS`, `SQLI_LEVEL`. Match the prefix to the skill_id exactly so a `grep -r SSRF_` finds every site that touches SSRF.
- **API field name:** camelCase, same root: `ssrfOobCallbackEnabled`, `rceAggressivePayloads`. Required in `fetch_agent_settings` mappings AND in the Prisma column `@map("ssrf_oob_callback_enabled")` snake_case.
- **Format placeholder:** lowercase snake_case of the setting key, without the skill prefix when readable: `{rce_oob_callback_enabled}`, `{sqli_level}`. The placeholder is what the LLM sees rendered; keep it readable.
- **Comment in `DEFAULT_AGENT_SETTINGS`:** one trailing line documenting WHY this is operator-changeable, not WHAT the value does. The `WHY` is what informs whether the toggle should live in the UI at all.

### Cross-checking against the layers

Once you have your tunable list locked, walk it through every layer it touches to confirm nothing dangles:

1. Layer 1 (`<skill>_prompts.py`): the placeholder appears in the template AND a sub-section / swap-block exists for it.
2. Layer 3 (`_build_builtin_skill_workflow_parts`): the setting is read with `get_setting('<KEY>', <default>)` and passed in the format arguments of `_seam.resolve_skill_part` (Pattern A) OR gates an `if`-append (Pattern B) OR resolves the swap-block argument (Pattern C). Layer 10 (`skill_parts.py`): a Pattern A placeholder is in its part's placeholder tuple; a Pattern B sub-section is its own `PLAIN` part with the condition as its gate.
3. Layer 5 (`project_settings.py`): key in `DEFAULT_AGENT_SETTINGS` AND a camelCase mapping in `fetch_agent_settings`.
4. Layer 6 (Prisma): if the tunable is per-project (most are), a column with `@default(...)` and `@map("snake_case_name")`. Pure prompt-bloat toggles can live in defaults only if you accept that all projects share them.
5. Layer 7 (frontend `<Skill>Section.tsx`): a labelled input that writes to the camelCase Prisma field via `updateField`. One-line operator-facing description. If you have 3+ booleans plus a value field, group them under a sub-heading.
6. Test (Phase 9 smoke + the per-skill test file): a unit test toggles each setting and asserts the rendered prompt changes (Pattern A: value visible in output; Pattern B: sub-section heading present/absent; Pattern C: correct swap-block selected).

If a tunable fails any of these checks, it is not yet a tunable -- it is dead config. Either complete the wiring or delete it.

---

## Phase 2: Write the workflow prompts (Layer 1)

Create [agentic/prompts/<skill_id>_prompts.py](../../../agentic/prompts/). Study the existing ones first to match the format, tone, and level of detail:

- Simple single-phase skill: [agentic/prompts/brute_force_credential_guess_prompts.py](../../../agentic/prompts/brute_force_credential_guess_prompts.py) (one big `HYDRA_BRUTE_FORCE_TOOLS` block + `HYDRA_WORDLIST_GUIDANCE`)
- Rich multi-section skill with format-string injection: [agentic/prompts/sql_injection_prompts.py](../../../agentic/prompts/sql_injection_prompts.py) (`SQLI_TOOLS` is a `.format()` template with `{sqli_level}`, `{sqli_risk}`, `{sqli_tamper_scripts}`)
- Conditional sub-sections: [agentic/prompts/xss_prompts.py](../../../agentic/prompts/xss_prompts.py) (`XSS_BLIND_WORKFLOW` only injected when the blind-callback setting is on)

One reachable port: a person's Kali sandbox takes inbound connections from a target on one port only (their pool port, or 4444 through their own tunnel), and the agent's payload settings block names it. Never write a literal LPORT, an `http.server` on a sandbox port, a second inbound port (a JNDI referral server on 1389/1099, a relay or `nc`/`socat` listener on a fixed port) or an `ngrok`/`chisel` of the skill's own: `agentic/tests/test_prompts_reverse_ports.py` scans every prompt file for them.

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

Edit [agentic/prompts/__init__.py](../../../agentic/prompts/__init__.py).

**3.1** Add a new re-export block alongside the existing `from .<skill>_prompts import (...)` blocks near the top of the file:

```python
# Re-export from <Skill Name> prompts
from .<skill_id>_prompts import (
    <SKILL_ID_UPPER>_TOOLS,
    <SKILL_ID_UPPER>_PAYLOAD_REFERENCE,  # if you split sub-sections
    # ...
)
```

**3.2** Add each constant name to the `__all__` list at the bottom of the file. Follow the existing grouping pattern (one `# Skill Name` comment then the constants).

---

## Phase 4: Wire the workflow into phase injection (Layer 3)

Edit `_build_builtin_skill_workflow_parts()` inside [agentic/prompts/__init__.py](../../../agentic/prompts/__init__.py). Its public wrapper `build_builtin_skill_workflow()` records which skill rendered, and every consumer calls that wrapper: the think node through `_inject_builtin_skill_workflow()` (a thin wrapper inside `get_phase_tools()`), Fireteam members, and LATS expand. A branch added here reaches all of them; do not add one anywhere else.

Add a new `elif` branch. Model it on the existing skill closest to yours. Every static part goes through `_seam.resolve_skill_part(skill_id, part_id, CONSTANT, kwargs)` (`kwargs` only where the part is a `.format` template), and the branch returns `parts`:

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
    parts.append(_seam.resolve_skill_part(
        "<skill_id>", "tools", <SKILL_ID_UPPER>_TOOLS, <skill>_settings))
    # Optional conditional sub-sections (plain parts: no format arguments):
    if <skill>_settings['your_setting'] and "<other_tool>" in allowed_tools:
        parts.append(_seam.resolve_skill_part(
            "<skill_id>", "oob_workflow", <SKILL_ID_UPPER>_OOB_WORKFLOW))
    parts.append(_seam.resolve_skill_part(
        "<skill_id>", "payload_reference", <SKILL_ID_UPPER>_PAYLOAD_REFERENCE))
    return parts
```

A bare `parts.append(<CONSTANT>)` or `parts.append(<CONSTANT>.format(...))` renders the same text, but it bypasses the seam: an approved plugin override never applies to that part, and `test_skill_parts_seam.py::test_registry_matches_call_sites` fails once the skill is in the golden recorder (Phase 4b). Only a block built from operator data (like the phishing branch's `PHISHING_SMTP_CONFIG` block) stays a plain append, and it is not registered.

**Ordering matters.** Place your branch before the `cve_exploit` branch if it should take precedence when CVE keywords overlap (e.g. an auth-bypass skill); otherwise keep it alphabetical with the other skills.

**If your skill needs post-exploitation guidance**, the `post_exploitation` branch of `get_phase_tools()` currently only special-cases user skills and the Metasploit post-expl prompts (the built-in workflow builder is not called in that phase). If your skill needs a custom post-expl prompt, add a branch there too. Most skills reuse the generic Metasploit post-expl when `metasploit_console` is allowed.

---

## Phase 4b: Register the workflow parts (Layer 10)

**4b.1** Edit [agentic/prompts/skill_parts.py](../../../agentic/prompts/skill_parts.py). Add one `_SPECS` entry per part your branch appends through the seam, in the order the branch appends them:

```python
("<skill_id>", "tools", "<skill_id>_prompts.<SKILL_ID_UPPER>_TOOLS", TEMPLATE,
 ("your_setting",), _ALWAYS),
("<skill_id>", "oob_workflow", "<skill_id>_prompts.<SKILL_ID_UPPER>_OOB_WORKFLOW", PLAIN, (),
 "<SKILL_ID_UPPER>_<SETTING> and <other_tool> allowed"),
("<skill_id>", "payload_reference", "<skill_id>_prompts.<SKILL_ID_UPPER>_PAYLOAD_REFERENCE", PLAIN, (), _ALWAYS),
```

The `part_id` equals the second argument at the call site. A part is `TEMPLATE` where the call passes format arguments, listing exactly the placeholder names its template uses, and `PLAIN` with `()` otherwise. The last field says when the branch includes the part; the branch's own gate applies on top.

**4b.2** In [agentic/tests/test_skill_parts_registry.py](../../../agentic/tests/test_skill_parts_registry.py), append the new parts to `EXPECTED` (and raise its length assertion) and each `TEMPLATE` part's placeholders to `EXPECTED_PLACEHOLDERS`. The file pins the registry because the webapp stores a plugin override against a part's key and the SHA-256 of its factory text.

**4b.3** In [agentic/tests/tools/record_skill_golden.py](../../../agentic/tests/tools/record_skill_golden.py), add the skill to `SKILLS`, its required tool to `REQUIRED_TOOL`, and the settings it reads to `ALL_ON` / `ALL_OFF`. Once you have confirmed the rendered text is what you intend, re-record `agentic/tests/fixtures/skill_workflow_golden.json` with the command in that file's docstring; `test_skill_workflow_golden.py` compares against it.

---

## Phase 5: Classification (Layer 4)

Edit [agentic/prompts/classification.py](../../../agentic/prompts/classification.py).

**5.1** Add a section constant next to the other `_<SKILL>_SECTION` constants at the top of the file:

```python
_<SKILL_ID_UPPER>_SECTION = """### <skill_id> - <Display Name>
- <one-line description>
- <bullet listing what the skill covers>
- Key distinction: <how this differs from neighboring skills (SQLi / XSS / unclassified)>
- Keywords: <comma-separated list>
"""
```

Keyword list guidance: pick terms the user is likely to type. Keep them disjoint from existing sections. If there is overlap (e.g. both SQLi and XSS can say "WAF bypass"), disambiguate in the "Key distinction" line.

**5.2** Add your skill to `_BUILTIN_SKILL_MAP`. Pick a priority letter no entry uses yet (the letter is informational):

```python
_BUILTIN_SKILL_MAP = {
    'phishing_social_engineering': (_PHISHING_SECTION, 'a', 'phishing_social_engineering'),
    # ... every other built-in skill ...
    '<skill_id>': (_<SKILL_ID_UPPER>_SECTION, '<unused letter>', '<skill_id>'),   # <-- new
}
```

**5.3** Add your entry to `_CLASSIFICATION_INSTRUCTIONS`:

```python
'<skill_id>': """   - **<skill_id>**:
      - <targeted yes/no classification questions, usually 3-4 bullets>""",
```

**5.4** Add your skill ID to BOTH ordered lists in `build_classification_prompt()`:

- the inline list of the `for skill_id in [...]` loop under "Attack Skill Types", which renders the sections in order
- `builtin_skill_ids`, which renders the classification criteria and builds `valid_types`

```python
for skill_id in ['phishing_social_engineering', 'brute_force_credential_guess',
                 # ... every other built-in skill ...
                 '<skill_id>']:  # <-- add here AND in builtin_skill_ids below
```

**5.5** (Optional, usually skip) If the skill must be excluded when RoE forbids it (like `denial_of_service` is gated on `ROE_ALLOW_DOS`), add a corresponding `enabled_builtins.discard('<skill_id>')` block next to the existing ones under `if get_setting('ROE_ENABLED', False):` at the top of `build_classification_prompt()`.

**5.6** (Optional, only if renaming defaults) `default_type` in `build_classification_prompt()` picks the classification for a vague request (`recon-unclassified`). Leave it.

---

## Phase 6: Project settings defaults (Layer 5)

Edit [agentic/project_settings.py](../../../agentic/project_settings.py).

**6.1** Add the skill ID to `ATTACK_SKILL_CONFIG.builtIn` in `DEFAULT_AGENT_SETTINGS`:

```python
'ATTACK_SKILL_CONFIG': {
    'builtIn': {
        'cve_exploit': False,
        'brute_force_credential_guess': False,
        # ... every other built-in skill ...
        '<skill_id>': <True_or_False>,    # <-- new
    },
    'user': {},
},
```

Default to `True` only for non-destructive, widely-useful skills. Default `False` anything that is invasive, noisy, or has legal/RoE implications.

**6.2** Add any per-skill tunables to `DEFAULT_AGENT_SETTINGS`. Follow the naming pattern of existing skills:

- SQLi uses `SQLI_LEVEL`, `SQLI_RISK`, `SQLI_TAMPER_SCRIPTS`
- XSS uses `XSS_DALFOX_ENABLED`, `XSS_BLIND_CALLBACK_ENABLED`, `XSS_CSP_BYPASS_ENABLED`

Example:

```python
# <Skill Name> Testing
'<SKILL_ID_UPPER>_<SETTING>': <default>,
```

These keys are what you read in `_build_builtin_skill_workflow_parts()` via `get_setting(...)` in Phase 4.

---

## Phase 7: Prisma schema default (Layer 6)

Edit [webapp/prisma/schema.prisma](../../../webapp/prisma/schema.prisma). The `attackSkillConfig` field of the `Project` model has a hardcoded JSON default:

```prisma
attackSkillConfig                    Json     @default("{\"builtIn\":{\"cve_exploit\":false,\"brute_force_credential_guess\":false,\"phishing_social_engineering\":false,\"denial_of_service\":false,\"sql_injection\":true,\"xss\":true,\"ssrf\":true,\"rce\":true,\"deserialization\":false,\"path_traversal\":true,\"access_control\":true,\"http_request_smuggling\":false,\"xxe\":true,\"crypto_attack\":true},\"user\":{}}") @map("attack_skill_config")
```

Add your skill ID to the JSON. Keep the escaping intact (note `\"`):

```prisma
attackSkillConfig    Json     @default("{\"builtIn\":{\"cve_exploit\":false,...,\"crypto_attack\":true,\"<skill_id>\":<true_or_false>},\"user\":{}}") @map("attack_skill_config")
```

Then run:

```bash
docker compose exec webapp npx prisma db push
```

Existing projects have their own stored `attackSkillConfig` JSON and will NOT auto-pick up the new key: a missing key means off on both sides (`builtIn` in `get_enabled_builtin_skills`, `user` in `get_enabled_user_skills`, where only an explicit `true` enables a skill). If you want existing rows to inherit the default, run:

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

**8.1** Edit [webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx](../../../webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx).

Add an entry to the `BUILT_IN_SKILLS` array. Pick an icon from `lucide-react` (add it to the file's `lucide-react` import if it is not there yet):

```tsx
{
  id: '<skill_id>',
  name: '<Display Name>',
  description: '<one-line description of what the skill does>',
  icon: <YourIcon size={16} />,
},
```

Add the same key to `DEFAULT_CONFIG.builtIn` (must match Phase 6 exactly).

If the skill has tunable settings that need their own sub-section UI (like `SqliSection.tsx`, `DosSection.tsx`, `BruteForceSection.tsx` (which exports `HydraSection`), `PhishingSection.tsx`), create a new sibling component and conditionally render it inside the main `AttackSkillsSection` where the other sub-sections are rendered (search the file for `<SqliSection`). If your skill only has simple boolean/number settings, skip this.

**8.2** Edit [webapp/src/app/graph/components/AIAssistantDrawer/phaseConfig.ts](../../../webapp/src/app/graph/components/AIAssistantDrawer/phaseConfig.ts).

Add a classification badge config inside `KNOWN_ATTACK_PATH_CONFIG`. Pick a color that is visually distinct from the existing ones:

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
- orange (#f97316) `ssrf`
- rose (#f43f5e) `rce`
- blue (#3b82f6) reserved for user skills
- gray reserved for unclassified

**8.3** Edit [webapp/src/app/api/users/[id]/attack-skills/available/route.ts](../../../webapp/src/app/api/users/[id]/attack-skills/available/route.ts) (Layer 8).

This API route's `BUILT_IN_SKILLS` array feeds the **skill-tooltip overlay** rendered above the chat input by `PhaseIndicatorBar.tsx` via the `useAttackSkillData` hook. If the new skill is not added here, it will NOT appear in the tooltip even though classification, badge, and project settings work. The user will see the active badge but the popup will be missing the entry.

Add an object matching the existing shape (id + name + description, NO icon -- the tooltip renders text only):

```ts
{
  id: '<skill_id>',
  name: '<Display Name>',
  description: '<one-line description matching the AttackSkillsSection card>',
},
```

Keep the order in this array consistent with the order in `BUILT_IN_SKILLS` of [AttackSkillsSection.tsx](../../../webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx) so the project-settings page and the drawer tooltip read the same.

**8.4** Edit [webapp/src/app/graph/components/AIAssistantDrawer/suggestionData.ts](../../../webapp/src/app/graph/components/AIAssistantDrawer/suggestionData.ts) (Layer 9).

Append a new `SESubGroup` block to `EXPLOITATION_GROUPS` (and to `INFORMATIONAL_GROUPS` / `POST_EXPLOITATION_GROUPS` only if the skill has phase-specific recon or post-exploitation actions worth pre-canning):

```ts
{
  id: '<skill_id>',
  title: '<Display Name>',
  items: [
    {
      suggestions: [
        { label: '<short verb phrase>', prompt: '<full instruction the agent will receive>' },
        // 3-6 examples covering the most common asks for this skill
      ],
    },
  ],
},
```

Guidelines for the prompt examples:
- Each `prompt` must be a self-contained instruction that the agent can execute. Do NOT reference variables or placeholders the agent won't have ("the target" is fine; "TARGET_HOST" is not).
- Cover the breadth of the skill: the most common payload class, an OOB / blind variant, an automation pivot, and a bypass / WAF-evasion case if applicable.
- Keep each `label` under 60 characters so the dropdown stays readable.
- Mention specific tools (`commix`, `sqlmap`, `dalfox`, `ysoserial`, etc.) so the agent knows which one to reach for.

Without this entry the new skill will be classified correctly when the user types a request, but the chat drawer's "Example prompts" dropdown will have no quick-launch buttons for it -- a noticeable UX regression versus the older skills.

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
| Toggle on UI does not persist | `DEFAULT_CONFIG` in [AttackSkillsSection.tsx](../../../webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx) and the Prisma JSON default drifted; make them match |
| Workflow prompt missing in agent logs | Phase guard failing: required tool not in `allowed_tools`; check `TOOL_PHASE_MAP` for the tool and phase |
| `KeyError` on `get_setting` | You referenced a setting in `_build_builtin_skill_workflow_parts()` that you forgot to add to `DEFAULT_AGENT_SETTINGS` |
| `test_skill_parts_registry.py` red | A part is not in `_SPECS` of [skill_parts.py](../../../agentic/prompts/skill_parts.py), or `EXPECTED` / `EXPECTED_PLACEHOLDERS` in the test were not extended (Phase 4b) |
| `test_skill_parts_seam.py::test_registry_matches_call_sites` red | A part is appended with a bare `parts.append(...)` instead of `_seam.resolve_skill_part(...)`, or its `part_id` / `TEMPLATE` kind differs from the registry |
| `test_skill_workflow_golden.py` red | The golden fixture was not re-recorded after an intended prompt change (command in the docstring of `record_skill_golden.py`) |

---

## Quick checklist

- [ ] `agentic/prompts/<skill_id>_prompts.py` created with `<SKILL_ID_UPPER>_TOOLS`
- [ ] Constants re-exported in [agentic/prompts/__init__.py](../../../agentic/prompts/__init__.py) + added to `__all__`
- [ ] New `elif` branch in `_build_builtin_skill_workflow_parts()` with phase guard, every static part appended through `_seam.resolve_skill_part(...)`, returning `parts`
- [ ] Every static part registered in `_SPECS` of [agentic/prompts/skill_parts.py](../../../agentic/prompts/skill_parts.py), `EXPECTED` / `EXPECTED_PLACEHOLDERS` extended in `test_skill_parts_registry.py`, the skill in `SKILLS` + `REQUIRED_TOOL` of `record_skill_golden.py`, golden fixture re-recorded (Layer 10)
- [ ] `<skill_id>` added to `KNOWN_ATTACK_PATHS` in [agentic/state.py](../../../agentic/state.py) (otherwise the Pydantic validator rejects classifier output)
- [ ] `_<SKILL_ID_UPPER>_SECTION` added and wired into `_BUILTIN_SKILL_MAP`
- [ ] `_CLASSIFICATION_INSTRUCTIONS[<skill_id>]` added
- [ ] `<skill_id>` added to BOTH ordered lists in `build_classification_prompt()`
- [ ] `ATTACK_SKILL_CONFIG.builtIn.<skill_id>` default added in [project_settings.py](../../../agentic/project_settings.py)
- [ ] Per-skill tunables (if any) added to `DEFAULT_AGENT_SETTINGS`
- [ ] [Prisma schema](../../../webapp/prisma/schema.prisma) `attackSkillConfig` default JSON updated + `prisma db push`
- [ ] **Every per-skill tunable that became a `Project` column is described in [recon_settings/registry.yaml](../../../recon_settings/registry.yaml)** (Layer 6b), and `python3 recon_settings/build.py` has been run. The build is red until every new column is described.
  - **`mcp: settable` is the right answer for an attack-skill tunable**, which inverts what this guide used to say. "It changes what the agent does to a live target, so deny it" sounds cautious and is not: the form can already set it, so denying it makes the API the weaker of two doors while changing nothing about what the agent may do. `parity.test.ts` fails that shape by design.
  - What actually bounds an attack-skill tunable is the pair the registry already carries: a real `bounds` or `values:` on the field, and the ENGAGEMENT LIMITS applied at scan start — `roeForbiddenTools`, `roeForbiddenCategories`, `roeAllowDos`, `roeAllowAccountLockout`, `roeAllowSocialEngineering` and `roeMaxSeverityPhase`, each checked in code before the tool executes, whatever the tunable says.
  - Follow the shipped skills for `group`: `attack` for aggression dials like `sqliLevel`, `egress` for out-of-band callbacks like `ssrfOobCallbackEnabled`, `wordlist` for payload sets like `rceAggressivePayloads`. The group is descriptive; it does not decide reachability.
  - A skill with no Prisma-backed tunables needs nothing: `attackSkillConfig` itself is already described.
- [ ] `BUILT_IN_SKILLS` entry added in [AttackSkillsSection.tsx](../../../webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx)
- [ ] `DEFAULT_CONFIG.builtIn.<skill_id>` added in [AttackSkillsSection.tsx](../../../webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx)
- [ ] `KNOWN_ATTACK_PATH_CONFIG[<skill_id>]` badge added in [phaseConfig.ts](../../../webapp/src/app/graph/components/AIAssistantDrawer/phaseConfig.ts)
- [ ] **`BUILT_IN_SKILLS` entry added in [api/users/[id]/attack-skills/available/route.ts](../../../webapp/src/app/api/users/[id]/attack-skills/available/route.ts)** (Layer 8: powers the chat-drawer skills tooltip; easy to miss, no UI failure on the project form if forgotten)
- [ ] **Suggestion-prompt block added to `EXPLOITATION_GROUPS` in [suggestionData.ts](../../../webapp/src/app/graph/components/AIAssistantDrawer/suggestionData.ts)** (Layer 9: 4-6 ready-to-send example prompts so the user has one-click invocations in the chat drawer)
- [ ] Stale skill-id comments swept (`grep -rn "<old skill id list>" webapp/src/`); update doc-comments in files like [webapp/src/lib/websocket-types.ts](../../../webapp/src/lib/websocket-types.ts) so they reflect the new skill set
- [ ] Agent container rebuilt; webapp rebuilt (or hot-reloaded in dev)
- [ ] End-to-end smoke test passed (keyword -> badge -> workflow in system prompt -> tooltip lists the new skill with checkmark when active -> suggestion-dropdown shows the example prompts)

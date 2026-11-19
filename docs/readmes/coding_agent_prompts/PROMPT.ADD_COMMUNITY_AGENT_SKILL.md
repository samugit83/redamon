# ADD A COMMUNITY AGENT SKILL

Add **[SKILL_NAME]** (e.g. `ssrf_exploitation`, `xxe_exploitation`, `race_conditions`) as a new **Community Agent Skill** shipped with RedAmon.

> **Scope**: a Community Agent Skill is a `.md` workflow file that users import via "Import from Community" in Global Settings > Agent Skills. Once imported, it becomes a row in the Postgres `UserAttackSkill` table, competes with built-in skills in the Intent Router classification, and gets its full markdown content injected into the agent's system prompt when selected. Use this flow when you have a battle-tested attack workflow you want to ship in the catalog but do NOT want to hardcode into Python. For hardcoded first-class skills, see [PROMPT.ADD_BUILTIN_AGENT_SKILL.md](PROMPT.ADD_BUILTIN_AGENT_SKILL.md). For reference docs (tool playbooks, theory), see [PROMPT.ADD_COMMUNITY_CHAT_SKILL.md](PROMPT.ADD_COMMUNITY_CHAT_SKILL.md).

---

## Architecture recap (read this first)

Community Agent Skills are the simplest of the three systems because everything is data: there is no classification code, no badge config, no per-project toggle logic, no Prisma change. You drop a file in the community folder, and the "Import from Community" flow does the rest.

```
agentic/community-skills/<skill_name>.md
         │
         ▼
  GET /community-skills  (agentic/api.py:2175)   catalog
  GET /community-skills/<skill_id>  (api.py:2202) full content
         │
         ▼
  POST /api/users/:id/attack-skills/import-community
  (webapp/src/app/api/users/[id]/attack-skills/import-community/route.ts)
         │
         ▼
  INSERT INTO user_attack_skills (Prisma model UserAttackSkill)
         │
         ▼
  Agent loads USER_ATTACK_SKILLS on every classification pass
  (project_settings.py:1024  get_enabled_user_skills())
         │
         ▼
  Classifier adds "user_skill:<id>" as a candidate
  (classification.py:333-336 builds the section from description or first 500 chars)
         │
         ▼
  When selected, resolve_user_skill() injects the full .md content
  (prompts/__init__.py:162)
```

| Layer | File | Touch? |
|---|---|---|
| 1. The workflow file | [agentic/community-skills/<skill_name>.md](../../../agentic/community-skills/) | YES |
| 2. The community README | [agentic/community-skills/README.md](../../../agentic/community-skills/README.md) | OPTIONAL (if an index exists) |
| 3. Wiki community table | [redamon.wiki/Agent-Skills.md](../../../redamon.wiki/Agent-Skills.md) "Community Skills" | YES if shipping publicly |
| 4. Everything else | N/A | NO CODE CHANGES |

The agentic `GET /community-skills` endpoint auto-discovers files by globbing the directory. There is nothing to register, and **no container rebuild is needed for the `.md` file itself**: `./agentic/community-skills` is volume-mounted read-only into the agent container at `/app/community-skills` (`./agentic/community-skills:/app/community-skills:ro` in the `agent` service's `volumes` in [docker-compose.yml](../../../docker-compose.yml)). Drop the file and it is picked up on the next `GET /community-skills` call. (A skill that references a NEW `kali_shell` CLI is the exception: the CLI lives in the baked kali-sandbox and agent images, so those must be rebuilt. See Phase 1 content rule 7.)

---

## Critical rules (READ BEFORE EDITING)

- **No container rebuild needed for the `.md` file.** `./agentic/community-skills` is volume-mounted read-only into the agent container (the `agent` service's `./agentic/community-skills:/app/community-skills:ro` mount in [docker-compose.yml](../../../docker-compose.yml)). Dropping a `.md` file there is instantly visible to the `/community-skills` endpoint. (This is an exception to the general rule that `agentic/` changes require rebuilding `agent`: that rule applies to Python code baked into the image, not to these two mounted directories.) **A skill that calls a new `kali_shell` CLI is NOT rebuild-free**: the binary and the `kali_shell` tool catalogue are baked in, so you must rebuild kali-sandbox and agent (content rule 7).
- **No Prisma migration needed.** Community skills are not a Prisma model on their own, they become `UserAttackSkill` rows on import. The schema already supports this.
- **Skills are per-user, not global, and import is by-name only.** Each user who wants this skill must click "Import from Community" in their Global Settings. Already-imported users will NOT auto-pick up new community skills, they need to re-import. Import skips any name the user already has (`import-community/route.ts`), so **editing an existing skill's `.md` does not reach users who already imported it**: re-import leaves their old copy in place. To adopt a rewrite they must delete the old skill first, then re-import. Call this out in the CHANGELOG whenever you change a shipped skill's content.
- **Skill content is capped at 500 KB** (`MAX_CONTENT_SIZE` in [webapp/src/lib/userSkills.ts](../../../webapp/src/lib/userSkills.ts)). Its whole text enters the agent's system prompt on every turn it is chosen, so keep a skill as short as its workflow allows.
- **Two different limits.** A user can hold up to 1000 skills (`MAX_SKILLS_PER_USER` in [webapp/src/lib/userSkills.ts](../../../webapp/src/lib/userSkills.ts)), but a project can enable at most 20 of them: the webapp refuses a 21st enabled skill, and the agent's `MAX_ENABLED_USER_SKILLS` in [agentic/project_settings.py](../../../agentic/project_settings.py) cuts the rest.
- **The first non-heading paragraph becomes the description.** [agentic/api.py:2188-2192](../../../agentic/api.py) extracts the first 200-char stripped non-`#` line as the description shown in the import dialog. Write that line well.
- **No em dashes anywhere.** Use hyphens or rephrase. Enforced project-wide.

---

## Phase 0: Pre-flight

1. Check [agentic/community-skills/](../../../agentic/community-skills/) for an existing file with the same or similar name. If found, STOP and decide whether to extend it instead.
2. Search for a related built-in skill. The authoritative list is `KNOWN_ATTACK_PATHS` in [agentic/state.py](../../../agentic/state.py) (today: `cve_exploit`, `brute_force_credential_guess`, `phishing_social_engineering`, `denial_of_service`, `sql_injection`, `xss`, `ssrf`, `rce`, `path_traversal`, `access_control`, `http_request_smuggling`, `xxe`, `crypto_attack`, `deserialization`), each with a section in [classification.py](../../../agentic/prompts/classification.py) `_BUILTIN_SKILL_MAP`. If your topic matches one, justify why the community version adds value (e.g. the SQLi community skill covers advanced bypasses beyond the sqlmap-focused built-in), AND add a `- vs. \`<builtin_id>\` (built-in): ...` line to the skill's "Disjoint from neighbouring skills" section telling the user to disable the built-in on import so the Intent Router routes to your skill predictably. Built-in and `user_skill:<id>` entries compete as "best match wins"; a silent same-class overlap means the classifier may pick either.
3. Decide: is this really an Agent Skill (phase-structured attack workflow) or a Chat Skill (reference doc for on-demand injection)? If it is flags, tables, syntax cheat sheets: use [PROMPT.ADD_COMMUNITY_CHAT_SKILL.md](PROMPT.ADD_COMMUNITY_CHAT_SKILL.md) instead. If it is "first run X, then pivot to Y, then report Z": this is the right prompt.

---

## Phase 1: Write the skill file

Create [agentic/community-skills/<skill_name>.md](../../../agentic/community-skills/). `<skill_name>` becomes the skill ID visible to the import endpoint (file stem, lowercase_snake, no extension).

The file stem also becomes the default `name` when rendered in the import UI (`md_file.stem.replace("_", " ").title()` at [agentic/api.py:2186](../../../agentic/api.py)). Pick a name that reads well in Title Case: `ssrf_exploitation` -> "Ssrf Exploitation".

### Required structure

Study the existing community skills to match the tone and level of detail:

- [agentic/community-skills/sqli_exploitation.md](../../../agentic/community-skills/sqli_exploitation.md) - advanced SQLi beyond sqlmap basics
- [agentic/community-skills/xss_exploitation.md](../../../agentic/community-skills/xss_exploitation.md) - reflected / stored / DOM XSS with WAF bypass
- [agentic/community-skills/ssrf_exploitation.md](../../../agentic/community-skills/ssrf_exploitation.md) - SSRF, cloud metadata, DNS rebinding
- [agentic/community-skills/api_testing.md](../../../agentic/community-skills/api_testing.md) - JWT, GraphQL, REST, 403 bypass

Canonical template (follow this shape, the wiki at [redamon.wiki/Agent-Skills.md](../../../redamon.wiki/Agent-Skills.md) documents it and the Intent Router expects it):

```markdown
# <Skill Name> Attack Skill

<Short paragraph: one-line summary. THIS BECOMES THE AUTO-DESCRIPTION
if the user does not provide one in the import dialog. The API extracts
the first non-heading stripped line at agentic/api.py:2188-2192.>

## When to Classify Here

Use this skill when the user requests <attack category>, including:
- <concrete trigger 1>
- <concrete trigger 2>
- <concrete trigger 3>

Keywords: <comma-separated, disjoint from other skills>

## Workflow

### Phase 1: Reconnaissance (Informational)

1. **<Step name>** - Use `query_graph` to <what to check in the graph first>.
2. **<Step name>** - Use `kali_shell` to run:
   ```
   <exact command>
   ```
3. **<Step name>** - <what to look for>.

Once <criterion> is met, **request transition to exploitation phase**.

### Phase 2: Exploitation

1. **<Primary attack step>**:
   ```
   <exact command or code>
   ```
2. **<Follow-up step>**:
   ```
   <command>
   ```
3. **<Verification>** - Confirm with <how to prove it worked>.

### Phase 3: Post-Exploitation  (optional, omit if not applicable)

1. **<Data extraction / lateral movement step>**
2. **<Persistence or escalation step>**

## Reporting Guidelines

- <Field 1 to include in the final report>
- <Field 2>
- <Impact demonstration, PoC artifact>

## Important Notes

- <Guardrail, flag, or limit>
- <Do-not-do warning>
- <Reference link (HackerOne report, CVE, writeup) - optional but valuable>
```

### Content rules

1. **Every step names the tool it uses.** The agent tools are the keys of `TOOL_REGISTRY` in [agentic/prompts/tool_registry.py](../../../agentic/prompts/tool_registry.py) (`query_graph`, `kali_shell`, `execute_curl`, `execute_code`, `execute_playwright`, `execute_nuclei`, `execute_hydra`, `execute_httpx`, `execute_arjun`, `execute_ffuf`, `metasploit_console`, ...). Do NOT invent tool names.
2. **Commands must be copy-pasteable.** Use fenced code blocks. No pseudo-code.
3. **Include the phase transition cue** at the end of Phase 1. The agent reads this literally and decides when to call `action="request_phase_transition"`.
4. **Keep the "When to Classify Here" section tight.** The classifier uses either the user-provided description from the import dialog or the first 500 characters of the file (see [classification.py:333-336](../../../agentic/prompts/classification.py)). Making the opening paragraph a clean one-liner that describes the skill is the single highest-ROI edit you can make for classification accuracy.
5. **No em dashes.**
6. **Target 200-800 lines.** Much shorter feels underbaked; much longer eats tokens every request.
7. **A `kali_shell` CLI must be installed AND documented, or it does not exist.** Every binary a step runs via `kali_shell` (sqlmap, dalfox, jwt_tool, ...) must already be in [mcp/kali-sandbox/Dockerfile](../../../mcp/kali-sandbox/Dockerfile). If it is NOT, you are adding a tool: follow [PROMPT.ADD_AGENTIC_TOOL.md](PROMPT.ADD_AGENTIC_TOOL.md) **Type A** - pin the install (a release version or a 40-hex commit, guarded by `tests/test_t17_build_pins.py`), add it to the `kali_shell` `description` in `tool_registry.py` (the `kali_toolbox` MCP tool serves that text verbatim, so an undocumented binary is invisible to external clients), add a stealth constraint in [agentic/prompts/stealth_rules.py](../../../agentic/prompts/stealth_rules.py) if it sends traffic, add a Dockerfile smoke test, then **rebuild kali-sandbox AND agent**. Prefer a tool already installed over adding one (e.g. sqlmap over ghauri, the `websockets` lib via `execute_code` over websocat).
8. **Every file path a command references must exist in the image.** Wordlists in the kali image are only `common.txt`, `raft-medium-directories.txt`, `big.txt` under `/usr/share/seclists/Discovery/Web-Content/`, the `Passwords/*` lists, and `/usr/share/wordlists/rockyou.txt` (see the SecLists block in the Dockerfile). Do not reference a SecLists path that is not downloaded; `ffuf`/tools fail on a missing `-w` file.

---

## Phase 2: Update the community index (optional)

If [agentic/community-skills/README.md](../../../agentic/community-skills/README.md) has a table of skills, add a row for the new one. Check the file first; do not invent structure.

---

## Phase 3: Update the wiki

Edit the "Community Skills" table in [redamon.wiki/Agent-Skills.md](../../../redamon.wiki/Agent-Skills.md) (the "### Community Skills" table; check the file for its current line range).

Add a row matching the existing format:

```markdown
| **[<Display Name>](https://github.com/samugit83/redamon/blob/master/agentic/community-skills/<skill_name>.md)** | [@<author>](https://github.com/<author>) | <focus area> | <1-2 highlights> |
```

Only include a GitHub link if the skill ships in the public repo. If the skill is local-only for this install, skip the wiki edit and tell the user.

---

## Phase 4: Verify

No rebuild. The file is live as soon as you save it (directory is volume-mounted).

### Smoke test

1. Hit the catalog endpoint directly to confirm the file is picked up:
   ```bash
   docker compose exec agent curl -s http://localhost:8080/community-skills | jq .
   ```
   Confirm your skill appears in `skills[]` with the expected `id` (file stem) and a reasonable auto-description.

2. Hit the content endpoint:
   ```bash
   docker compose exec agent curl -s http://localhost:8080/community-skills/<skill_name> | jq .
   ```

3. In the webapp: Global Settings (gear icon, top right) > Agent Skills > **Import from Community**. The dialog shows how many will be imported. Confirm. If you had already imported previously, your new one will show in the "imported" count and duplicates in the "skipped" count.

4. Create a fresh project. Project Settings > Agent Skills > scroll to the "User Agent Skills" section. Your skill appears as a toggle, OFF: a skill with no key in the project's `attackSkillConfig.user` is off, so a new project has none enabled. Turn it on and save (the key is the skill's database id, not its file stem).

5. Open the AI Assistant drawer, send a message matching your "When to Classify Here" keywords. Watch the badge:
   - Matches: badge shows `SKILL` (blue), tooltip shows your skill name.
   - Does not match: badge shows the unclassified fallback (gray).

6. Agent logs (`docker compose logs -f agent`) should show the full markdown content injected into the system prompt under `## User Attack Skill: <name>`. Grep for a unique marker line from your file.

7. Toggle the skill OFF in project settings, resend the same message. Badge should fall back to unclassified.

### Failure triage

| Symptom | Likely cause |
|---|---|
| Skill not in `/community-skills` catalog | File not in `./agentic/community-skills/` (that exact path), or filename is `README.md` (excluded at [api.py:2178](../../../agentic/api.py)), or missing `.md` extension. The directory is volume-mounted so there is no rebuild to miss |
| "Import from Community" shows `total: 0` | webapp cannot reach `AGENT_API_URL`. Check `docker compose logs webapp` and the `AGENT_API_URL` env var in the webapp service |
| Import works but classifier never picks the skill | Description is generic or overlaps with a built-in. Edit the description via Global Settings > Agent Skills > pencil icon. Or rewrite the opening paragraph of the .md |
| Badge shows `SKILL` but workflow not in system prompt | Unlikely; `resolve_user_skill()` is non-conditional. Check agent logs for errors parsing the `attack_path_type` |
| "Too large" error on import | File exceeds 500 KB. Trim the workflow |
| "You have 1000 skills, the maximum" error on import | User is at the library cap. They need to delete an existing skill first |
| Cannot enable the skill in a project | The project already has 20 user skills enabled. Turn one off first |

---

## Quick checklist

- [ ] [agentic/community-skills/<skill_name>.md](../../../agentic/community-skills/) created with the canonical structure
- [ ] First non-heading paragraph is a crisp one-line summary (auto-description)
- [ ] "When to Classify Here" section lists concrete triggers + keywords
- [ ] Workflow steps reference real agent tools (`query_graph`, `kali_shell`, `execute_curl`, etc.)
- [ ] Phase 1 ends with "request transition to exploitation phase" cue
- [ ] File is under 500 KB
- [ ] No em dashes anywhere
- [ ] (Optional) [agentic/community-skills/README.md](../../../agentic/community-skills/README.md) updated
- [ ] (Optional, if shipping publicly) [redamon.wiki/Agent-Skills.md](../../../redamon.wiki/Agent-Skills.md) Community Skills table updated
- [ ] `GET /community-skills` returns the new entry (no rebuild, directory is volume-mounted)
- [ ] End-to-end: imported via UI, appears in project settings, classifier picks it on matching message, full content shows in agent system prompt

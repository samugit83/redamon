# ADD A CHAT SKILL

Add **[SKILL_NAME]** (e.g. `ad_kill_chain`, `ffuf`, `jwt_cheatsheet`) as a new **Chat Skill** shipped with RedAmon.

> **Scope**: a Chat Skill is an on-demand reference `.md` injected into the agent via the `/skill <name>` command in the chat drawer, or the lightning-bolt skill picker. It does NOT affect classification, phase routing, or tool selection. It is a tactical reference doc (tool playbooks, vulnerability theory, framework notes, scan-mode guides). Users import the shipped catalog via "Import from Community" in Global Settings > Chat Skills, then activate skills mid-session with `/skill <name>`. For phase-structured attack workflows, see [PROMPT.ADD_COMMUNITY_AGENT_SKILL.md](PROMPT.ADD_COMMUNITY_AGENT_SKILL.md). For hardcoded first-class skills, see [PROMPT.ADD_BUILTIN_AGENT_SKILL.md](PROMPT.ADD_BUILTIN_AGENT_SKILL.md).

---

## Architecture recap (read this first)

Chat Skills live in [agentic/skills/<category>/](../../agentic/skills/). The loader at [agentic/skill_loader.py](../../agentic/skill_loader.py) recursively globs `**/*.md`, parses YAML frontmatter, and exposes them via `GET /skills` and `GET /skills/<skill_id:path>` in [agentic/api.py](../../agentic/api.py).

```
agentic/skills/<category>/<skill_name>.md  (with YAML frontmatter)
         │
         ▼
  skill_loader.list_skills()   (agentic/skill_loader.py:53-92)
    returns [{ id, name, description, category, file }]
         │
         ▼
  GET /skills                    (agentic/api.py:535-545)  catalog
  GET /skills/<skill_id:path>    (agentic/api.py:548-558)  full content
         │
         ▼
  POST /api/users/:id/chat-skills/import-community
  (webapp/src/app/api/users/[id]/chat-skills/import-community/route.ts)
         │
         ▼
  INSERT INTO user_chat_skills (Prisma model UserChatSkill at
  webapp/prisma/schema.prisma:941-954)
         │
         ▼
  User activates via /skill <name> or lightning-bolt picker
  (webapp/src/app/graph/components/AIAssistantDrawer/InputArea.tsx)
         │
         ▼
  useSendHandlers.activateSkill -> WebSocket SKILL_INJECT message
  (webapp/src/lib/websocket-types.ts:22 SKILL_INJECT = 'skill_inject')
         │
         ▼
  Agent injects the full .md content into the current conversation as guidance
  (no classification, no phase branching, full content as-is)
```

Key differences from Agent Skills:
- **Category-aware**: files live under `agentic/skills/<category>/...`. Category = top-level directory name. Default is `general` if you put the file at the root.
- **Per-user, not per-project**: imports land in `UserChatSkill`, available across all the user's projects.
- **Manually activated**: no classifier routing, user types `/skill <name>`.
- **Phase-agnostic**: full content is injected regardless of phase.
- **Cap of 50 per user** (versus 20 for agent skills).

| Layer | File | Touch? |
|---|---|---|
| 1. The skill `.md` with YAML frontmatter | [agentic/skills/<category>/<skill_name>.md](../../agentic/skills/) | YES |
| 2. Category folder | [agentic/skills/<category>/](../../agentic/skills/) | YES (create if new) |
| 3. Wiki catalog | [redamon.wiki/Chat-Skills.md](../../redamon.wiki/Chat-Skills.md) | YES if shipping publicly |
| 4. Everything else (classification, Prisma, UI code) | N/A | NO CODE CHANGES |

---

## Critical rules (READ BEFORE EDITING)

- **No container rebuild needed.** `./agentic/skills` is volume-mounted read-only into the agent container at [docker-compose.yml:418](../../docker-compose.yml#L418). Dropping a `.md` file into `agentic/skills/<category>/` is instantly visible to the loader. (This is an exception to the general rule that `agentic/` changes require rebuilding `agent`: that rule applies to Python code like `skill_loader.py` itself, not to the mounted `skills/` tree it reads.)
- **YAML frontmatter is required** for a good UX. [skill_loader.py:29-50](../../agentic/skill_loader.py) parses `---`-delimited frontmatter. Without it, `name` falls back to `file_stem.replace("_", " ").title()` and `description` is empty.
- **The skill ID is the path under `agentic/skills/` WITHOUT the extension**, with `/` as separator. `agentic/skills/active_directory/ad_kill_chain.md` has ID `active_directory/ad_kill_chain`. This is what `/skill <name>` matches against (partial, case-insensitive match via the frontend autocomplete at [InputArea.tsx](../../webapp/src/app/graph/components/AIAssistantDrawer/InputArea.tsx)).
- **Path traversal is blocked.** `load_skill_content()` at [skill_loader.py:95-118](../../agentic/skill_loader.py) resolves the path and refuses anything outside the skills directory.
- **Content size cap is 50 KB.** Enforced at the chat-skills POST route, same as agent skills.
- **Max 50 skills per user.** If importing a large catalog, communicate the cap.
- **No Prisma migration needed.** `UserChatSkill` already exists at [webapp/prisma/schema.prisma:941-954](../../webapp/prisma/schema.prisma).
- **No em dashes anywhere.** Use hyphens or rephrase. Enforced project-wide.

---

## Phase 0: Pre-flight

1. List existing skills in [agentic/skills/](../../agentic/skills/). Confirm there is not already one covering the topic. Use [agentic/skills/active_directory/ad_kill_chain.md](../../agentic/skills/active_directory/ad_kill_chain.md) as the current reference example (the only default-shipped Chat Skill at time of writing).
2. Decide: is this really a Chat Skill? Use Chat Skills for:
   - Tool CLI playbooks (flags, syntax, common patterns): `ffuf`, `nuclei`, `sqlmap` cheat-sheets
   - Vulnerability theory and test vectors: `ssrf`, `race_conditions`, `xxe`
   - Framework / stack notes: `nextjs`, `graphql`, `firebase`
   - Scan mode guides: `deep`, `quick`, `standard`
   - Coordination prompts: `root_agent`
   
   If it is a step-by-step attack workflow with phase transitions, use [PROMPT.ADD_COMMUNITY_AGENT_SKILL.md](PROMPT.ADD_COMMUNITY_AGENT_SKILL.md) instead.
3. Pick a category from the existing tree: `active_directory`, `api_security`, `cloud`, `coordination`, `frameworks`, `mobile`, `network`, `protocols`, `reporting`, `scan_modes`, `social_engineering`, `technologies`, `tooling`, `vulnerabilities`, `wireless`. If none fits, create a new category folder.

---

## Phase 1: Create the category folder (if new)

```bash
mkdir -p "agentic/skills/<category>"
```

The category is derived from the top-level directory name relative to `agentic/skills/`. It is what shows as the badge on the skill card in Global Settings > Chat Skills and in the autocomplete grouping.

There is also a dropdown of categories in the upload UI at [webapp/src/app/settings/page.tsx](../../webapp/src/app/settings/page.tsx) (search for the Chat Skills category dropdown, it lists: `general`, `vulnerabilities`, `tooling`, `scan_modes`, `frameworks`, `technologies`, `protocols`, `coordination`). If you use a category not in that list, the dropdown will not include it for manual uploads, but Import from Community will still work because the backend accepts any string.

---

## Phase 2: Write the skill file

Create [agentic/skills/<category>/<skill_name>.md](../../agentic/skills/).

### Required YAML frontmatter

[skill_loader.py:29-50](../../agentic/skill_loader.py) reads only `name` and `description` from the frontmatter. Other keys are ignored.

```markdown
---
name: <short human-readable name>
description: <one-line summary, used by the skill picker and autocomplete>
---

# <Title>

<body...>
```

- `name`: appears in the active-skill badge above the chat input and in the picker list. Keep it short (2-5 words).
- `description`: appears in the picker/autocomplete and on the skill card in Global Settings. 1-2 sentences.

### Content rules

Chat Skills are simpler than Agent Skills. The wiki documents this at [redamon.wiki/Chat-Skills.md "Writing a Chat Skill File"](../../redamon.wiki/Chat-Skills.md):

- No phase structure (no "Phase 1: Reconnaissance", etc.)
- No "When to Classify Here" section (Chat Skills are not classified)
- Focus on reference material: flags, tables, patterns, test vectors, examples

Canonical shape (copy from [agentic/skills/active_directory/ad_kill_chain.md](../../agentic/skills/active_directory/ad_kill_chain.md) for a long-form example, or the template below for a short playbook):

```markdown
---
name: <name>
description: <one-line summary>
---

# <Tool or Topic> Playbook

<One paragraph: what this doc covers, when the agent should use it.>

## Canonical syntax

<baseline command or shape>

## High-signal flags

- `-u <url>` target URL containing FUZZ
- `-w <wordlist>` wordlist input
- `-mc <codes>` match status codes
- `-ac` auto-calibration
- `-noninteractive` disable interactive console mode

## Agent-safe baseline

<the command/pattern the agent should default to when asked to run this tool>

## Common patterns

- **<Pattern name>**: `<command>`
- **<Pattern name>**: `<command>`

## Known gotchas

- <flag interaction, default pitfall, output-parsing quirk>
```

Additional rules:

1. **Optimize for token density.** Chat Skills are injected into the conversation and stay there. Bloat burns the user's context window on every message.
2. **Target 100-400 lines.** Some complex topics (AD kill chain) justify 500+, but aim low.
3. **Reference real agent tools** when pointing to command executions: `kali_shell`, `execute_curl`, `execute_code`, `execute_playwright`, `query_graph`.
4. **No em dashes.**
5. **No placeholder lorem.** Everything in the file goes straight into the LLM context.

---

## Phase 3: Update the wiki

Edit the "Default Chat Skills Library" and/or "Community Chat Skills" tables in [redamon.wiki/Chat-Skills.md](../../redamon.wiki/Chat-Skills.md) (current tables at lines ~217-235).

Add a row matching the format:

```markdown
| **[<Display Name>](https://github.com/samugit83/redamon/blob/master/agentic/skills/<category>/<skill_name>.md)** | <Category> | <Focus line> |
```

Skip this step if the skill is local-only for this install.

---

## Phase 4: Verify

No rebuild. The file is live as soon as you save it (`./agentic/skills` is volume-mounted).

### Smoke test

1. Confirm the loader sees the file:
   ```bash
   docker compose exec agent curl -s http://localhost:8000/skills | jq '.skills[] | select(.id | contains("<skill_name>"))'
   ```
   Expected output: a dict with `id`, `name`, `description`, `category`, `file`. Verify `name` and `description` match your frontmatter. If they show the auto-generated title-case fallback, your frontmatter is malformed (check the `---` delimiters and `key: value` spacing).

2. Hit the content endpoint:
   ```bash
   docker compose exec agent curl -s "http://localhost:8000/skills/<category>/<skill_name>" | jq .
   ```
   Path traversal protection: IDs outside `agentic/skills/` return 404.

3. In the webapp: **Global Settings > Chat Skills** tab. Click **Import from Community**. The dialog shows how many will be imported. Confirm. Your skill should now appear as a card with the correct name, category badge, and description.

4. Alternative: click the lightning-bolt button in the chat input area. The "Import from Community" button and "Upload .md" button live at the top of the picker (see [InputArea.tsx](../../webapp/src/app/graph/components/AIAssistantDrawer/InputArea.tsx) around the skill picker dropdown). Skills imported this way are the same `UserChatSkill` rows.

5. In any chat session, type `/skill <skill_name>` (or `/s` to trigger autocomplete, then select your skill). The active-skill badge appears above the input with your `name` and `category`.

6. Send a message. The agent now has your full `.md` content in its context. Ask a question clearly answerable only from the skill content to confirm injection.

7. Type `/skill remove` (or click X on the badge) to deactivate. Confirm the badge disappears.

8. Try the combined-command form: `/skill <skill_name> <your question>`. Skill activates AND message sends in one step.

### Failure triage

| Symptom | Likely cause |
|---|---|
| `/skills` catalog does not include the file | File not in `./agentic/skills/<category>/` (that exact path), missing `.md` extension, or the loader cannot parse the YAML frontmatter (check `docker compose logs agent` for `Failed to parse skill file`). The tree is volume-mounted so there is no rebuild to miss |
| `name` shows as `File_stem Title Case` instead of your frontmatter value | Frontmatter malformed. Must start with `---` on line 1, close with `---` on its own line, use `key: value` pairs |
| `description` empty in UI but present in file | Same frontmatter issue |
| `/skill <name>` does not match | The autocomplete does partial, case-insensitive match on the skill's `name` field (not the ID). If the `name` frontmatter differs from the filename, use the `name` |
| Skill appears in Global Settings but not in chat picker | The chat picker fetches `GET /api/users/:id/chat-skills` on drawer mount. Refresh the page |
| Import from Community returns `total: 0` | webapp cannot reach `AGENT_API_URL` (check webapp env + `docker compose logs webapp`) |
| "Too large" error | Content exceeds 50 KB |
| "Maximum of 50 skills" error | User is at cap |

### Re-importing when you update a shipped skill

The import endpoint skips duplicates by `name`. If you edit a shipped skill and want existing users to pick up the new version:
- They must either **delete** the old entry first (trash icon in Global Settings > Chat Skills) and re-import, OR
- You can manually update the `content` via the PUT route at [webapp/src/app/api/users/[id]/chat-skills/[skillId]/route.ts](../../webapp/src/app/api/users/[id]/chat-skills/[skillId]/route.ts) (note: current PUT handler only updates description; you may need to extend it for content updates, or users must delete-and-reimport).

Flag this to the user when shipping a skill update.

---

## Quick checklist

- [ ] Category folder exists under [agentic/skills/](../../agentic/skills/) (or created if new)
- [ ] [agentic/skills/<category>/<skill_name>.md](../../agentic/skills/) created
- [ ] YAML frontmatter with `name:` and `description:` on lines 1-4 (opened and closed with `---`)
- [ ] Content is reference-style (flags, tables, patterns), not a phase-structured workflow
- [ ] Commands reference real agent tools when relevant
- [ ] File is under 50 KB
- [ ] No em dashes anywhere
- [ ] (Optional, if shipping publicly) [redamon.wiki/Chat-Skills.md](../../redamon.wiki/Chat-Skills.md) catalog table updated
- [ ] `GET /skills` returns the new entry with correct `name`, `description`, `category` (no rebuild, directory is volume-mounted)
- [ ] End-to-end: Import from Community -> appears in Global Settings > Chat Skills -> activates via `/skill <name>` -> badge appears -> agent answers from skill content -> `/skill remove` deactivates

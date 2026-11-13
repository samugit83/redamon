# README.PLUGIN_SDK

The reference for **plugin authors**: everything a RedAmon plugin can declare, call and
show, as implemented in **plugin platform 1.0.0**. It is the public contract of the platform
(design principle 6 of [README.PLUGINS.md](README.PLUGINS.md)): a later platform version may
add to it (a minor version) but changes nothing here without a major version.

Read [README.PLUGINS.md](README.PLUGINS.md) first for *why* the platform is built this way
(isolation, the Gateway, human approval). This file is *what* you write. Plugins live in the
separate repository [`samugit83/redamon-plugins`](https://github.com/samugit83/redamon-plugins)
(branch `master`), whose README covers releasing; its first plugin,
[`skiller/`](https://github.com/samugit83/redamon-plugins/tree/master/skiller), is a complete
worked example.

Every value below is checked against the code it names. Where this file and the code
disagree, the code is right and this file is a bug.

---

## 1. A plugin in one paragraph

A plugin is a folder: a manifest (`plugin.json`), Python **actions** under `engine/`, optional
**screen descriptions** under `ui/`, optional **data migrations** under `migrations/`. An admin
installs a released archive of it on the Plugins page. A user then triggers an action from a
place the manifest declared (the chat gear menu, a built-in skill's row in project settings, the
plugin's own page). The action runs in an isolated worker process in the plugin runner and
receives a `ctx` whose `ctx.sdk` is its only way out: every call goes to the Gateway, which checks
the call token and the permissions the admin granted. The action returns a JSON object; the core
UI decides what to show. A plugin never ships JavaScript, never touches the database, never holds
an LLM key and never changes agent behaviour by itself: it can only **propose** a change that a
person approves in core UI.

---

## 2. The folder

```
<plugin>/
  plugin.json      the manifest (§3)
  README.md        what the plugin does, the data it reads and stores, its limits
  CHANGELOG.md     one "## [x.y.z]" section per released version
  engine/          Python actions; engine/__init__.py is required
  vendor/          optional: bundled pure-Python dependencies (§10)
  ui/              optional: screen descriptions, JSON (§9)
  migrations/      optional: NNNN_up.py / NNNN_down.py data migrations (§8)
  tests/           pytest against the SDK's fakes (§11); never packed
  eval/            optional evaluation harness; never packed
```

- The plugin id matches `^[a-z][a-z0-9-]{1,39}$` and is not a reserved name; it is the folder
  name in the repository and on the plugins volume.
- The archive is a gzip'd POSIX ustar with one top folder named after the plugin, regular files
  and directories only (no links, devices, absolute or climbing paths, at most 2,000 entries)
  and at most `PLUGIN_ARCHIVE_MAX_BYTES` unpacked (20 MiB by default). `tools/pack.py` in
  `redamon-plugins` writes exactly that, byte-identical on every run
  ([archive.ts](../../webapp/src/lib/plugins/archive.ts) is the reader that enforces it).
- Plugin code imports only the Python standard library, the SDK package `redamon_plugin_sdk`,
  its own `engine` package and what its `vendor/` folder holds. Plugins never import each other;
  `tools/validate.py` refuses both.

---

## 3. The manifest (`plugin.json`)

Strict: a key this platform version does not know is refused, never ignored. The schema is
[schemas/manifest.ts](../../webapp/src/lib/plugins/schemas/manifest.ts); its JSON Schema export
is `webapp/src/lib/plugins/schemas/json/` (`npm run plugins:schemas`), which `redamon-plugins`
validates against.

| Field | Type and limits | Meaning |
|---|---|---|
| `id` | `^[a-z][a-z0-9-]{1,39}$`, not reserved | The plugin's id. |
| `version` | `x.y.z` | This release. |
| `displayName` | 1-60 chars | Shown on cards, menus and tiles. |
| `description` | 1-500 chars | Shown on the card. |
| `platform` | a range such as `">=1.0.0 <2.0.0"` (comparators `>= > <= < =` on full `x.y.z`) | Platform versions this release runs on. The platform installs the newest release whose range includes it. |
| `dataVersion` | integer ≥ 1 | The shape of the data this release stores (§8). |
| `permissions` | subset of `session:read`, `llm:invoke`, `override:skill.text`, `override:user_skill.text` (platform 1.1.0), no duplicates | What the admin consents to at install (§4.2). |
| `llmFeature` | `{description: 1-200 chars}` | Required with `llm:invoke` (and only then): the text of the plugin's tile in Global Settings → LLM Providers → Models by feature. |
| `actions` | at most 50 | Entry points (§4). |
| `actions[].id` | `^[a-z][a-z0-9_]{1,39}$`, unique | Named by contributions and screens. |
| `actions[].entry` | `engine/<path>.py:<function>` | An `async def` function. |
| `actions[].timeoutSeconds` | 1-3600 | Capped again by `PLUGIN_ACTION_MAX_TIMEOUT` (900 by default). |
| `actions[].async` | boolean | Run as a job with a progress window (§4.4). |
| `actions[].llm` | boolean | The action calls a model: needs `llm:invoke`; the UI asks the user to choose a model first. |
| `actions[].resultScreen` | `ui/<path>.json`, listed in `screens` | Accepted and checked; in 1.0.0 no extension point opens it (a form's own `resultScreen` does, §9). |
| `contributes` | object, keys below | The UI extension points the plugin uses (§9.1). An unknown key is refused as an unknown extension point. |
| `contributes.nav` | `{label, icon, screen}` | One page of the plugin at `/plugins/<id>`. |
| `contributes["chat.session.actions"]` | at most 5 of `{label, icon?, action?, coreScreen?, pick?}`, exactly one of `action` / `coreScreen` | Items in the chat gear menu. `coreScreen: "skill.text.versions"` opens the core versions window and needs `override:skill.text`. `pick: "session.skill"` (platform 1.1.0, with an `action` only, needs `session:read` and `override:skill.text` or `override:user_skill.text`) makes the core show its skill picker first; see §4.1. |
| `contributes["project.skills.row"]` | at most 3 of `{label, action}` | Buttons in each built-in skill row of project settings. |
| `screens` | at most 50 `ui/<path>.json`, unique | Every screen file the plugin has. A screen not listed here cannot be opened. |

`icon` is one of `puzzle`, `sparkles`, `history`, `list`, `file-text`, `settings`, `play`,
`search`, `shield`, `book-open`, `bot`, `bug`, `clock`, `database`, `star`, `target`, `zap`
([extensionPoints.ts](../../webapp/src/lib/plugins/extensionPoints.ts)): a fixed list, so a plugin
button cannot borrow a core icon's look.

At install the platform also checks what a schema cannot: every `entry` file is in the archive,
every action a contribution or screen names is declared, every screen that is used (the `nav`
screen, a `resultScreen`, a screen a button or row action opens) is listed in `screens`, and every
screen file parses ([installChecks.ts](../../webapp/src/lib/plugins/installChecks.ts)).

---

## 4. Actions

### 4.1 The signature

```python
async def run(ctx, params: dict) -> dict:
    ...
```

- `params` is the JSON object the UI sent (at most 64 KB): a screen's `source.params`, a form's
  fields, a row action's `pass` fields, or `{}` from a menu item.
- A menu item with `pick: "session.skill"` (platform 1.1.0) sends `params.pick =
  {kind: "session.skill", point, target, ref}`: the skill the person picked among those the
  session used, of the points your plugin is granted. `ref` is a built-in id or
  `user_skill:<id>`; `point` is `skill.text` or `user_skill.text`; `target` is the target group
  to pass to `sdk.override`. RedAmon re-derives it from the session and refuses a pick not in its
  list (`400 invalid_pick`), so you may trust it as the person's choice; your action should still
  work without it (an older RedAmon never sends one). One job runs per session: a start while one
  runs answers that job, whatever was picked.
- The return value must be a JSON object of at most 2 MB. Anything else fails the call with
  `invalid_result`.
- Raise `PluginError(code, message)` (from `redamon_plugin_sdk`) to fail with a message the user
  sees: `code` matches `^[a-z][a-z0-9_]{0,63}$` (otherwise it becomes `plugin_error`) and the
  message is cut at 2,000 characters. Any other exception reaches the user only as "The plugin
  failed. Details are in its log." (`internal_plugin_error`); its traceback goes to the plugin's
  log (§12).

### 4.2 `ctx`

[context.py](../../services/plugin_runner/sdk/redamon_plugin_sdk/context.py), set by the platform
for one call:

| Field | Value |
|---|---|
| `plugin_id`, `version` | The running plugin and version. |
| `user_id` | The effective user who started the action. |
| `project_id` | Set when the action was started from a project (a session, a project's skill row). |
| `session_id`, `conversation_id` | Set when started from a chat session. |
| `job_id` | Set only inside an async action. |
| `sdk` | The Gateway client (§5), bound to this call's token. |

The webapp decided all of these before the runner saw the call: the project is the user's own or
shared with them at the levels your permissions need (below), the session is the user's own or one
its author shared with the project, the permissions are both granted by the admin and declared in
the manifest.

**Projects shared with the user.** With RBAC sharing on, `project_id` may name another person's
project the user collaborates on. Your plugin then runs for that user at the levels its
permissions ask: every permission needs a Read + Write share, `llm:invoke` also Use AI agent; a
plugin that declares no permission runs only for the project's owner. `ctx.user_id` stays the person
who started the action (your `owner="user"` rows, the daily model-call cap); `owner="project"` rows
are the project's, shared by everyone who runs the plugin there. The webapp and the Gateway check
it on every call, so a share revoked or narrowed while the action runs ends it with `not_found`.

### 4.3 What the UI does with a result

| Started from | The result | What the user sees |
|---|---|---|
| Chat gear menu, sync action | `{"reviewProposal": {"extensionPoint": "skill.text", "changeSetId": "…"}}` | The core review window for that proposal. The webapp keeps the field only when the change set exists, is this plugin's, is in the caller's scope and names that point ([actions.ts](../../webapp/src/lib/plugins/actions.ts) `checkReviewProposal`). |
| Chat gear menu, sync action | `{"message": "…"}` | A notice with the message (or "Done" without one). |
| Chat gear menu, async action | the job's result (same fields) | The core job window shows progress, then the review window or the message. |
| A screen's `source` | a page: any object; a list or table: `{"items": [...], "next": "…"\|null}` | The screen's data (§9.3). |
| A form | any object | Its `resultScreen` opened with the result as inputs, or the result's `message`. |
| A button or row action | any object | Its `message`, or "Done". |

An action with `llm: true` first passes the **model gate**: if the user has not chosen a model for
the plugin in Models by feature, a core window asks for one before the action is sent. On a shared
project the owner's choice counts, never the user's: without one the start answers `409
owner_model_required`.

### 4.4 Async actions and jobs

With `async: true` the webapp answers `202 {jobId}` at once and the action runs as a **job**
([jobs.ts](../../webapp/src/lib/plugins/jobs.ts)). The user watches it in the core job window and
may cancel it.

- One active job per (plugin, action, user, project, session): a second start answers the job
  already running.
- `await ctx.sdk.jobs.progress(message, fields)` updates the window: `message` at most 300
  characters, at most 20 `fields` of at most 200 characters each.
- Cancelling raises `asyncio.CancelledError` inside the action: let it propagate.
- The job ends `succeeded` with the result, or `failed` with `{code, message}`. It fails with
  `timeout` past its deadline, `runner_restarted` when the runner restarted under it,
  `invalid_result` when the result cannot be stored (U+0000, an unpaired surrogate),
  `result_too_large` above 2 MB, `plugin_unavailable` when the plugin stopped serving
  (disabled, uninstalled, revoked, updated to another version) before it ended,
  `context_gone` when its project or session was deleted, and `plugin_not_allowed` when an admin
  limited the plugin to permission sets its user holds none of while it ran. A `cancelled` report nobody asked for
  is recorded as `failed`.
- Jobs are kept 30 days.

### 4.5 Limits

| Limit | Value |
|---|---|
| Timeout | `timeoutSeconds`, capped by `PLUGIN_ACTION_MAX_TIMEOUT` (900 s) |
| Actions at once per plugin | `PLUGIN_MAX_CONCURRENT_ACTIONS` (4); more answer `429 plugin_busy` |
| Gateway calls per call token | `PLUGIN_GATEWAY_CALLS_PER_TOKEN` (600), then `429 call_budget_exceeded` |
| A call token | lives only as long as its action (`403 action_ended`) or job (`403 job_ended`) |

---

## 5. The SDK

`ctx.sdk` ([client.py](../../services/plugin_runner/sdk/redamon_plugin_sdk/client.py)) has five
groups. Every call is a coroutine (`await`); each is one POST to `/api/plugin-gateway/v1/<op>`
with the call token. Every check that matters happens in the Gateway, so a plugin that bypasses
the SDK gains nothing. Failures raise `PluginError` with the Gateway's code, or one of the client's
own: `gateway_timeout` (30 s; 600 s for `llm.invoke`), `gateway_unreachable`, `gateway_error`,
`gateway_bad_response`, `gateway_response_too_large` (16 MB), `invalid_value` (not JSON),
`invalid_query`, `not_in_job`. The wire format is pinned by
[contract_cases.json](../../services/plugin_runner/sdk/contract_cases.json), run against both the
fake and the real Gateway.

### 5.1 Refusals common to every call

The Gateway frame ([gateway.ts](../../webapp/src/lib/plugins/gateway.ts) `withGateway`) checks, in
order:

| Code | Status | Why |
|---|---|---|
| `invalid_token` | 401 | No token, a forged or expired one. |
| `action_ended` / `job_ended` | 403 | The action or job the token was issued for is over. |
| `call_budget_exceeded` | 429 | The token made its 600 calls. |
| `body_too_large` | 413 | Body above its limit: 64 KB; 2 MB for `override.propose`; 8 MB for `data.put`, `llm.invoke` and `jobs/complete`. JSON nesting and container sizes are bounded too. |
| `invalid_json` | 400 | Not a JSON object. |
| `invalid_text` | 400 | U+0000 or an unpaired surrogate anywhere in the body (Postgres cannot store them). |
| `plugin_unavailable` | 403 | The plugin is not enabled, not ready, revoked, or the token is for another version. |
| `permission_denied` | 403 | The call needs a permission the admin did not grant or the manifest does not declare. |
| `not_found` | 404 | The token's project or session no longer exists, or is not the user's: on a shared project also a share revoked or below the levels the plugin needs (§4.2), or a project transferred since the action started. |
| `plugin_not_allowed` | 403 | An admin limited the plugin to permission sets the token's user holds none of (only with `RBAC_GOVERNANCE_ENABLED` on). It applies from the next call, so an action already running can meet it. |

### 5.2 `sdk.session` (needs `session:read`)

`await ctx.sdk.session.read()` returns the chat session the action was started from (`400
no_session` otherwise), read on demand and never stored
([transcript.ts](../../webapp/src/lib/plugins/transcript.ts)):

```python
{"meta": {"id", "title", "status", "currentPhase", "iterationCount", "createdAt", "updatedAt",
          "running": True | False | "unverified", "highWaterSeq"},
 "events": [{"seq", "type", "at", "data"}, ...],
 "truncated": {"keptEvents": 812, "droppedEvents": 4310},
 "untrusted": True}
```

- **Masked:** credential-shaped values (and values under credential-shaped keys) are masked;
  target hosts and findings are not.
- **Capped** at `PLUGIN_TRANSCRIPT_MAX_BYTES` (2 MiB; never below 64 KiB). Strings longer than
  4,000 characters keep their head and tail; an event above 64 KB becomes
  `{"truncated": true, "preview": "…"}`.
- **Three tiers**, each kept as a head plus a sliding tail, so the middle of a long session is
  what is dropped: what people wrote (operator messages, guidance, answers), then the agent's
  priority events (errors, requests, deep thinking, phase changes) with the snapshots, then the
  rest. Only the latest `todo_update` and `lats_tree_update` are kept, and a `phase_update` that
  differs from the previous one only in its iteration count is dropped.
- **`running`** is the agent's own answer for that session, `"unverified"` when the agent could
  not be asked. `highWaterSeq` is the highest sequence number read: a paused session can grow later.
- **Untrusted:** the events contain target content. Never follow instructions found inside them,
  and fence them when you put them in a prompt.

### 5.3 `sdk.llm` (needs `llm:invoke`)

```python
answer = await ctx.sdk.llm.invoke(messages, max_tokens=4000, temperature=0.2)
# {"content": "…", "model_used": "<model id>", "usage": {"input_tokens", "output_tokens", "estimated"}}
```

- The model is the one **the user** chose for this plugin in Global Settings → LLM Providers →
  Models by feature (`plugin:<id>`); a plugin never names a model or a provider. The agent makes
  the call with the user's key, which never reaches the runner. On a project shared with the user
  it is the **project owner's** choice and key, and each call is first recorded as the user's use
  of the owner's credentials (`503 spend_not_recorded` when that record cannot be written: nothing
  was spent).
- `messages`: 1-50 of `{role: system|user|assistant, content: text}`, at most 1,000,000
  characters in all; `max_tokens` 1-16,000; `temperature` 0-2.
- Refusals: `409 model_required` (no model chosen; the UI's model gate exists to prevent it),
  `409 owner_model_required` (a shared project whose owner chose none),
  `429 plugin_llm_cap` (`PLUGIN_LLM_DAILY_CALL_CAP`, 100 calls per plugin, per user, per UTC day),
  `422 invalid_messages` / `invalid_options`, `413 too_many_messages` / `messages_too_large`, and
  the agent's own errors passed through with their codes.

### 5.4 `sdk.data` (no permission: a plugin's own data)

A plugin keeps JSON in RedAmon's generic store
([dataStore.ts](../../webapp/src/lib/plugins/dataStore.ts)), keyed by (plugin, owner,
collection, key). Install never changes the database schema.

```python
await ctx.sdk.data.put("notes", "n1", {"text": "…", "kind": "lesson"}, owner="user", ttl_seconds=86400)
value = await ctx.sdk.data.get("notes", "n1")              # None when missing or expired
page = await ctx.sdk.data.query("notes", where={"kind": "lesson"}, order="-updated", limit=50)
# {"items": [{"key", "value", "updatedAt", "expiresAt"}], "next": "<cursor>" | None}
n = await ctx.sdk.data.count("notes", where={"kind": "lesson"})
deleted = await ctx.sdk.data.delete("notes", "n1")         # True when a row was deleted
```

| Rule | Value |
|---|---|
| `owner` | `"user"` (the effective user) or `"project"` (only when the action has a project). A row dies with its owner. |
| `collection` | `^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,63}$`; names starting with `__` are the platform's (`reserved_collection`). |
| `key` | 1-512 characters, no NUL. |
| `value` | Any JSON (no NUL), at most `PLUGIN_DATA_MAX_VALUE_BYTES` (1 MiB; `413 value_too_large`). |
| `ttl_seconds` | 1 s to 10 years; an expired row is invisible to every read. |
| Quotas | Per plugin: `PLUGIN_DATA_MAX_ROWS` (10,000) rows, `PLUGIN_DATA_MAX_BYTES` (50 MiB), `PLUGIN_DATA_MAX_ROWS_PER_OWNER` (2,000): `413 quota_exceeded` with `quota` and `limit`. A write that would exceed one first deletes the plugin's expired rows. |
| `query` | `prefix` on the key, `where` of 1-5 top-level fields of the stored object, ANDed, by **jsonb equality**: text of at most 512 characters, a finite number, `true`, `false` or `null`; a boolean never equals a number, `1` equals `1.0`. `order`: `-updated` (default), `updated`, `key`, `-key`. `limit` up to 200 (default 50). |
| Paging | Pass `next` back as `cursor` with the same query. Inserts and deletes between pages never skip or repeat a row; an update moves a row in the `updated` orders (in `-updated` behind the cursor, not returned again), and an `updated` walk is bounded by its newest row at the start, so a walk that writes back as it reads ends. A cursor from another query, or a forged one, is `400 invalid_cursor`. |
| `count` | How many live rows `query` would page through with the same `prefix` and `where`. |

### 5.5 `sdk.override` (needs `override:skill.text` or `override:user_skill.text`)

Two behaviour extension points:
- `skill.text` (needs `override:skill.text`): a proposal of new text for a built-in agent skill's
  static workflow parts (the parts the agent registers in
  [skill_parts.py](../../agentic/prompts/skill_parts.py)). Nothing changes for the agent until a
  person approves it in the core review window.
- `user_skill.text` (needs `override:user_skill.text`, platform 1.1.0): a proposal of new text for
  one of the **user's own** skills that the call's session used. Approving it never changes that
  skill: RedAmon saves the text as a **new** skill of the user's. See "User skills" below.

```python
target = await ctx.sdk.override.get("skill.text", "sql_injection")
proposal = await ctx.sdk.override.propose(
    "skill.text", "sql_injection",
    {"<partId>": "<the whole new text of that part>"},
    note="Why this version is better, for the reviewer.",
    meta={"sessionHighWaterSeq": 4120},     # your own data, shown back to you
    scope="user",                           # or "project" inside a project
)
# {"changeSetId": "…", "fromRevision": 2, "proposedRevisionLabel": "v3"}
await ctx.sdk.override.withdraw(proposal["changeSetId"])    # a pending proposal of yours
```

- **`get(point, target_group)`** answers `{point, targetGroup, displayName, parts, active,
  pendingCount, limits}`. Each part is `{partId, text, sha256, chars, maxChars, kind,
  placeholders}`: the **factory** text. A `template` part must keep exactly its `placeholders`
  (`{name}`) and double any new literal brace; a `plain` part is used verbatim. `active` is the
  version the agent runs for this call's project (or the user, outside a project) with its parts'
  text, or `None` for factory text; it is shown only while it was built on the current factory
  text. `limits` holds each part's `maxChars` and the whole skill's (`PLUGIN_SKILL_TEXT_MAX_GROWTH`,
  1.5 × the factory size).
- **`propose(point, target_group, parts, *, note, meta=None, scope="user", based_on=None)`**
  stores a **complete snapshot**: every part whose text differs from the factory text. A part you
  do not send is factory text in that version, so to build on the active version, start from
  `active.parts` and send them all. The SDK sends back the factory hashes of the last `get` of the
  same target (`readSha256`), or of the `based_on` answer you pass: if a RedAmon update changed
  the factory text since, the proposal is refused with `409 factory_changed`; read the target
  again and redo it. `fromRevision` is the revision of the proposal's scope that `get` showed; when
  `get` showed another scope's version, the proposal is recorded as built on factory text and
  `meta.basedOn` names what was shown, so the reviewer is warned that approving replaces the
  scope's active version.
- **Validation** is the agent's ([plugin_api.py](../../agentic/plugin_api.py) `POST
  /plugins/skill-parts/validate`): each part's `maxChars`, the whole-skill bound, the placeholder
  rules, no invisible or control characters, no imitation of the headings that follow the skill
  text in the prompt (guardrails, rules of engagement). A refusal is `422 invalid_proposal` with
  the errors per part.
- Other refusals: `400 invalid_proposal` (no note, `meta` not an object, no part changed),
  note at most 4,000 characters, `meta` at most 64 KB of JSON, at most 50 parts;
  `400`/`404 invalid_target` (unknown point or skill); `409 too_many_pending` (5 pending
  proposals per scope and skill); `404 not_found` (withdrawing someone else's).
- Versions are numbered per scope by a counter that never goes back, so a deleted `v3` is never
  reused. Approval, rejection, deletion and reset are core actions of the scope's owner (or an
  admin; for a project scope also a co-owner with Manage), never a plugin's.
- The platform records with every proposal the plugin version, conversation and job of the call
  (from its token); those keys, and the platform's other meta keys, are dropped from your `meta`.

**User skills (`user_skill.text`).**

```python
target = await ctx.sdk.override.get("user_skill.text", params["pick"]["target"])
# {"point": "user_skill.text", "targetGroup": "<skill id>", "displayName": "My SQLi flow v2",
#  "description": "…", "parts": [{"partId": "body", "text": "…", "sha256": "…", "chars": 1234,
#  "maxChars": 512000, "kind": "plain", "placeholders": []}], "active": None, "pendingCount": 0,
#  "limits": {"skillMaxChars": 512000, "parts": {"body": 512000}},
#  "lineage": {"rootName": "My SQLi flow", "version": 2}}
proposal = await ctx.sdk.override.propose("user_skill.text", target["targetGroup"],
                                          {"body": new_text}, note="Why", scope="user")
# {"changeSetId": "…", "fromRevision": None, "proposedRevisionLabel": None}
```

- Only a skill the **session** of the call used (the agent's record of the text it rendered, or
  the skill label in older sessions), owned by the call's user, and not quarantined. Every other
  case, unknown ids included, is the same `404 invalid_target`; outside a session `get` is `400
  no_session`. A skill whose name, description or text holds a key or token in a recognised format (a private key, a
  JWT, a cloud or API token) is never given to a plugin: `422 skill_contains_credentials`.
- One plain part, `body`, used verbatim (no placeholders; braces written normally). `maxChars`
  counts UTF-16 code units, like JavaScript's `.length`: measure with
  `redamon_plugin_sdk.client.js_length`, not `len`.
- `propose` takes `scope="user"` only (`400 invalid_proposal` otherwise) and parts exactly
  `{"body": text}` (`422`). A `get` of the same target in the action (or `based_on`) is
  **required**: the SDK sends back its hash (`readSha256`), and a text the user edited since is
  `409 factory_changed`. The agent then validates the text (`POST /plugins/text/validate`): not
  empty, no NUL, within the limit, different from the current text, and no reserved marker, Rules
  of Engagement heading or hidden character the current text did not already hold (`422
  invalid_proposal`; `503` when the agent is down).
- Five proposals may wait per skill (`409 too_many_pending`). `withdraw` needs the permission of
  the set's own point.
- What happens next is RedAmon's: the person saves the proposal as a new skill (named after the
  source with the next ` vN`), optionally in place of the source in a project; saving needs your
  plugin enabled and **at the version that made the proposal**. If the catalog revokes that
  version, its waiting proposals are withdrawn and the skills saved from them quarantined.

### 5.6 `sdk.jobs`

`progress(message, fields=None)`, inside an async action only (§4.4); elsewhere `not_in_job`. A
job's end is reported by the runner, not by plugin code.

---

## 6. Permissions

| Permission | Grants | The admin is told |
|---|---|---|
| `session:read` | `sdk.session.read` | The plugin reads the chat session it is started from, with secrets masked. |
| `llm:invoke` | `sdk.llm.invoke` | The plugin calls the model each user chooses for it, counted against that user. |
| `override:skill.text` | `sdk.override.*` at `skill.text`, the `skill.text.versions` core screen | The plugin may propose new text for built-in skills; a person approves every version. |
| `override:user_skill.text` | `sdk.override.*` at `user_skill.text` (platform 1.1.0) | The plugin may propose new versions of the user's own skills from the sessions that used them, reading their text; saving creates a new skill and never changes the original; a skill holding credential-shaped values is never given to it. |

The wording is [permissions.ts](../../webapp/src/lib/plugins/permissions.ts) `PERMISSION_TEXT`. An
update that adds a permission asks the admin for consent again.

---

## 7. Errors a user sees

A refusal raised by the SDK and not caught reaches the user through the action's failure: the
action fails with that `PluginError`'s code and message. Catch the ones you can handle
(`model_required`, `plugin_llm_cap`, `factory_changed`, `too_many_pending`,
`skill_contains_credentials`) and raise your own `PluginError` with a sentence the user can act
on.

---

## 8. Data migrations

A release whose `dataVersion` is higher than the installed one ships one migration per step;
`NNNN_up.py` moves data from version N-1 to N, `NNNN_down.py` from N back to N-1 (N from 2 to
9999):

```python
# migrations/0002_up.py
from redamon_plugin_sdk import DELETE

def migrate_row(row):
    # row = {"collection", "key", "ownerType", "value"}; return the new value, or DELETE
    if row["collection"] != "notes":
        return row["value"]
    value = dict(row["value"])
    value["kind"] = value.pop("type", "lesson")
    return value
```

- `migrate_row` is a plain (not `async`) function, given one row at a time; return the row's new
  value (any JSON) or the `DELETE` sentinel to drop it.
- The platform copies the live rows aside, runs every step over every row of the copy **for every
  owner**, in batches, in a temporary worker of the version that ships the step, checks each answer
  like a write (and the quotas after each step), then swaps the copy in together with the new
  version in one transaction ([migrations.ts](../../webapp/src/lib/plugins/migrations.ts)). Any
  failure discards the copy: the old data and the old version stay as they were.
- Migration code gets **no call token** and no Gateway: it transforms rows and nothing else.
- A rollback runs the `down` steps; without them a rollback across a data change is refused
  (`no_down_migration`). Reinstalling a release whose `dataVersion` is lower than the data kept
  from a newer one is refused (`data_newer_than_release`).

---

## 9. Screens

A plugin's UI is **described**, never shipped: JSON drawn by core React components from a fixed
set of primitives. The platform's web app is compiled once, and JavaScript from a plugin would act
with the user's session, so plugin text is rendered escaped or as Markdown without images, and
every link lands on an exit page first.

### 9.1 Where a plugin appears

| Point | Declared as | Drawn where |
|---|---|---|
| `chat.session.actions` | menu items | The chat's gear menu, in a group after "Agent Skills", labelled with the plugin's name and badge. |
| `project.skills.row` | buttons | Each built-in skill row of a saved project's Agent Skills settings. |
| `nav` | one page | An "Open" entry on the plugin's card on `/plugins`, and the page at `/plugins/<id>` (sub-screens at `/plugins/<id>/<path without ui/ and .json>`). Not a header entry: the header has one Plugins button. |
| `skill.text` (behaviour) | the `override:skill.text` permission | The core review and versions windows, which a plugin can open (`reviewProposal`, `coreScreen`) but never draw. |
| `user_skill.text` (behaviour) | the `override:user_skill.text` permission | The core skill picker before the action (`pick`), and the core save-as-new-skill review (`reviewProposal` with `extensionPoint: "user_skill.text"`). |

### 9.2 The primitives

The schema is [schemas/screen.ts](../../webapp/src/lib/plugins/schemas/screen.ts). A screen file is
one node, usually a `page`; at most 6 levels deep and 200 nodes; text at most 2,000 characters.

| `type` | Fields | Notes |
|---|---|---|
| `page` | `title?`, `source?`, `children` (≤ 50) | `source` loads one object; children bind its fields. |
| `list` | `title?`, `source`, `itemTitle`, `itemSubtitle?`, `rowActions?`, `emptyText?` | Paged list of items. |
| `table` | `title?`, `source`, `columns` (1-20 of `{field, label?, format?: text\|date\|number}`), `rowActions?`, `emptyText?` | Paged table. |
| `form` | `title?`, `fields` (1-30), `submit: {action, label?}`, `resultScreen?` | Field kinds `text`, `textarea`, `number`, `select` (with `options`), `checkbox`; `required`, `placeholder`, `maxLength`, `default`. |
| `select` | `name`, `label`, `options`, `default?` | A standalone choice. |
| `button` | `label`, exactly one of `action` / `screen`, `params?`, `confirm?`, `tone?: primary\|secondary\|danger` | `confirm` asks first. |
| `markdown` | `content` | Safe Markdown, no images. |
| `textDiff` | `title?`, `before`, `after` | Side-by-side text. |
| `badge` | `content`, `tone?: neutral\|info\|success\|warning\|danger` | |
| `emptyState` | `title`, `text?` | |

`rowActions`: at most 5 of `{label, exactly one of action / screen, pass}`; `pass` names at most
20 row fields, and only those reach the action or the opened screen.

### 9.3 Binding rules

- `source` is `{action, params?}`. Its params are the source's own, overridden by the screen's
  **inputs** (a row action's `pass` fields, or a form's result for its `resultScreen`), which is
  how a detail screen learns which item to show.
- A `page` source answers one object; `markdown`, `textDiff` and `badge` take `{text}` (static) or
  `{field}` (a field of that object). A field value shows only if it is a string, number or
  boolean; objects and arrays render as nothing.
- A `list` or `table` source answers `{items: [...], next}`. "Load more" calls the action again
  with the same params plus `cursor: next` and appends: pass `cursor` straight to
  `sdk.data.query`.
- Field names match `^[A-Za-z_][A-Za-z0-9_]{0,63}$`.

A new primitive or extension point is a platform change (a minor version), never a plugin's.

---

## 10. The runner environment

| | |
|---|---|
| Python | 3.11 (`python:3.11-slim`, pinned by digest in [Dockerfile](../../services/plugin_runner/Dockerfile)) |
| Start | `python -I -S`: no site-packages, no environment-driven paths. `sys.path` = the SDK, the plugin's folder, its `vendor/`. |
| Importable | The standard library, `redamon_plugin_sdk`, `engine`, `vendor/` contents. The supervisor's own libraries (FastAPI and others) are invisible. |
| Process | One worker per (plugin, version), its own UID (20000-29999), `nice 10`, undumpable, a private temp directory (`TMPDIR`). |
| Limits | Address space `PLUGIN_WORKER_MEM_MB` (512 MB), processes and threads `PLUGIN_WORKER_NPROC` (64), 256 open files, 64 MB per written file; the container has its own memory, CPU and PID caps. |
| Network | None but the Gateway, through the `plugin-gateway` proxy, on an internal network with no route out. |
| Environment | `PATH`, `LANG`, `PYTHONDONTWRITEBYTECODE`, `PYTHONHASHSEED`, `REDAMON_GATEWAY_URL`; nothing else, no secret. |
| Files | The plugin's folder is read-only. Keep state in `sdk.data`, not on disk. |

**`vendor/`.** Put pure-Python dependencies there, as importable packages or modules. A
dependency with compiled code (a C extension) cannot run: it would need a platform change that adds
it to the runner image.

---

## 11. Testing and local development

**Unit tests** use the SDK's doubles
([testing.py](../../services/plugin_runner/sdk/redamon_plugin_sdk/testing.py)):

- `FakeSdk(...)`: the real `Sdk` over an in-memory Gateway that applies its main refusals
  (permissions, owner, reserved collections, unknown parts, five pending proposals); inspect
  `.proposals`, `.progress`, `.rows`; `set_active(...)` makes a version active as if approved;
  `add_user_skill(id, name, content, *, used_in_session=True, owner=None, ...)` adds one of the
  user's own skills for `user_skill.text` (the same key and token formats as RedAmon, over the
  name, description and text; its text checks are a subset of the agent's, never stricter).
  Passing here is necessary, not sufficient: not every quota is applied.
- `ScriptedLlm([...])`: answers model calls from a queue (a string, a dict, or a `PluginError` to
  raise) and records every prompt; an empty queue raises `llm_script_exhausted`.
- `make_context(...)`: a `ctx` with a `FakeSdk` built from the same ids (`transcript=`, `llm=`,
  `registry=`, `permissions=`).

In `redamon-plugins`, `tools/run_tests.sh <plugin>` runs a plugin's tests in `python:3.11-slim`
(each plugin's `tests/conftest.py` puts its folder and the SDK on `sys.path`, §14) against the
lowest platform SDK its range accepts (`.platform-sdk/<version>/`, synced from this
repository), and `tools/validate.py <plugin>` applies every rule of §2, §3 and §9 before CI does.

**Against a real RedAmon** there is no folder-loading mode: install the way production does, from
a catalog signed with a **development key** that the instance trusts through
`PLUGINS_EXTRA_TRUSTED_KEYS`, with **Install from file** on the Plugins page. The commands are in
the `redamon-plugins` README ("Developing a plugin against a local RedAmon"). The Plugins page warns
while an extra key is trusted; remove it afterwards.

---

## 12. Logs

- Everything the worker writes (stdout and stderr, tracebacks) is the plugin's log: the last 1,000
  lines per plugin are kept in memory (lines cut at 4,000 characters, control characters removed)
  and every line also goes to the runner's container log with a `[plugin:<id>@<version>]` prefix,
  rotated by compose (10 MB × 3).
- Admins read the in-memory log on the plugin's details on the Plugins page (`GET
  /api/plugins/<id>/logs`). Do not print transcripts or target data: the log is read by admins and
  kept on disk.
- The webapp logs every Gateway call as `[plugins] gateway <op> plugin=<id> status=<n> ms=<n>`, and
  install, update, approval and reset in the audit log.

---

## 13. Catalog, trust and revocation

A plugin reaches users only as a release in the **signed catalog** of `redamon-plugins`: the
archive's SHA-256 and the requested permissions are pinned by an Ed25519 signature that RedAmon
verifies with the public keys it ships. A signed catalog has no expiry; RedAmon keeps the highest
serial it has seen and treats a lower one as a stale copy. A released version can be **revoked** in
a new signed catalog: within one reconcile interval its actions, menus and approved skill versions
stop everywhere (the agent goes back to the factory text). Details: README.PLUGINS.md §6.2 and §6.4.

---

## 14. A complete small example

A plugin with its own page listing notes, a form to add one, and a row action to delete one.

`plugin.json`:

```json
{
  "id": "notes-demo",
  "version": "1.0.0",
  "displayName": "Notes demo",
  "description": "Keeps short notes per user and shows them on a page.",
  "platform": ">=1.0.0 <2.0.0",
  "dataVersion": 1,
  "permissions": [],
  "actions": [
    { "id": "list_notes", "entry": "engine/main.py:list_notes", "timeoutSeconds": 30 },
    { "id": "add_note", "entry": "engine/main.py:add_note", "timeoutSeconds": 30 },
    { "id": "delete_note", "entry": "engine/main.py:delete_note", "timeoutSeconds": 30 }
  ],
  "contributes": {
    "nav": { "label": "Notes", "icon": "file-text", "screen": "ui/home.json" }
  },
  "screens": ["ui/home.json"]
}
```

`ui/home.json`:

```json
{
  "type": "page",
  "title": "Notes",
  "children": [
    {
      "type": "form",
      "title": "Add a note",
      "fields": [{ "name": "text", "label": "Note", "kind": "textarea", "required": true, "maxLength": 500 }],
      "submit": { "action": "add_note", "label": "Add" }
    },
    {
      "type": "table",
      "source": { "action": "list_notes" },
      "columns": [
        { "field": "text", "label": "Note" },
        { "field": "createdAt", "label": "Added", "format": "date" }
      ],
      "rowActions": [{ "label": "Delete", "action": "delete_note", "pass": ["key"] }],
      "emptyText": "No notes yet."
    }
  ]
}
```

`engine/main.py` (with an empty `engine/__init__.py`):

```python
import time
import uuid

from redamon_plugin_sdk import PluginError

COLLECTION = "notes"


async def list_notes(ctx, params):
    page = await ctx.sdk.data.query(COLLECTION, order="-updated", limit=50, cursor=params.get("cursor"))
    items = [{"key": row["key"], **row["value"]} for row in page["items"]]
    return {"items": items, "next": page["next"]}


async def add_note(ctx, params):
    text = str(params.get("text") or "").strip()
    if not text:
        raise PluginError("empty_note", "Write something first.")
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    await ctx.sdk.data.put(COLLECTION, uuid.uuid4().hex, {"text": text[:500], "createdAt": created})
    return {"message": "Note added."}


async def delete_note(ctx, params):
    key = params.get("key")
    if not isinstance(key, str) or not await ctx.sdk.data.delete(COLLECTION, key):
        raise PluginError("not_found", "That note no longer exists.")
    return {"message": "Note deleted."}
```

`tests/conftest.py` puts the plugin folder and the platform SDK on `sys.path`, the way a worker
does (`tools/run_tests.sh` sets `REDAMON_PLATFORM_SDK`):

```python
import os
import pathlib
import sys

PLUGIN = pathlib.Path(__file__).resolve().parents[1]
for path in (str(PLUGIN), os.environ["REDAMON_PLATFORM_SDK"]):
    if path not in sys.path:
        sys.path.insert(0, path)
```

`tests/test_main.py`:

```python
import asyncio

from redamon_plugin_sdk.testing import make_context

from engine.main import add_note, delete_note, list_notes


def test_add_list_delete():
    async def scenario():
        ctx = make_context(permissions=[])
        assert (await add_note(ctx, {"text": "check the login form"}))["message"] == "Note added."
        page = await list_notes(ctx, {})
        assert [n["text"] for n in page["items"]] == ["check the login form"]
        await delete_note(ctx, {"key": page["items"][0]["key"]})
        assert (await list_notes(ctx, {}))["items"] == []

    asyncio.run(scenario())
```

What the user sees, once an admin has installed it: the plugin's card on `/plugins` has an
**Open** entry; the page shows the form and the table; **Add** calls `add_note` and the notice says
"Note added."; the table pages through `list_notes` ("Load more" passes the cursor); **Delete**
sends only that row's `key` to `delete_note`.

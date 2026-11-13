# RedAmon as an MCP Server (inbound)

RedAmon can expose itself to **external AI agents** over the Model Context
Protocol. A customer's own agent, an MCP-capable client, or a scripted pipeline
connects in, authenticates as **one RedAmon user**, and can do three things
scoped to that user's own projects: start a full recon pipeline, change a narrow
set of recon tuning settings, and query the attack-surface graph. A token that
opts in also reads the projects other people shared with its user (see "Shared
projects reach a token only when it opts in").

> **Two MCP features, opposite directions.** Do not confuse them.
>
> | | Direction | Where |
> | --- | --- | --- |
> | **MCP Tool Plugins** ([README.MCP.md](README.MCP.md)) | **outbound** — RedAmon is the *client* of servers you register | Global Settings → *MCP Tool Plugins* |
> | **MCP Server** (this document) | **inbound** — other agents are the *clients*, RedAmon is the *server* | Global Settings → *MCP Server* |

---

## 1. What is and is not exposed

**Exposed.** The table is a summary; the generated [MCP API Reference](https://github.com/samugit83/redamon/wiki/MCP-API-Reference) is rendered from the live `tools/list` and is the authoritative list.

| Tool | What it does | Permission |
| --- | --- | --- |
| `list_projects` | The token owner's projects. Nothing else is visible. | `recon:read` |
| `get_recon_status` | Whether a scan is running, and its phase. | `recon:read` |
| `get_recon_settings` | Every setting `update_recon_settings` can change, plus the (read-only) engagement scope and the `updatedAt` to pass back. Credentials are never returned. | `recon:read` |
| `graph_summary` | Count per node type + relationships present; `coverage`, per stamping module (`js_recon`, `nuclei`), the BaseURLs `complete` / `partial` / `no_input` / `failed` and the live ones `not_scanned` (`{recorded: false}` before any stamp; absent, never zeros, when unreadable), computed inside the agent's same fixed `summary` op; and, on a settled graph far smaller than the project's history (under a tenth of the current or newest saved version's `nodeCount`, or empty after a completed full scan), `warning: "graph_data_missing"` with `graphDataMissing`. See `graphSummary` / `graphDataMissing` in `webapp/src/lib/mcp/tools.ts`. | `recon:read` |
| `graph_schema` | What the graph *means*. No arguments, no data. | `recon:read` |
| `query_graph` | Ask the graph a question in natural language. | `recon:read` (+ `graph:cypher` for raw Cypher) |
| `kali_toolbox` | The Kali sandbox's installed toolset, by category. Reads code, not the container. | `recon:read` |
| `start_recon` | Start the full recon pipeline. | `recon:scan` (+ `recon:overwrite` for `mode:"overwrite"`) |
| `stop_recon` | Stop a running scan. | `recon:scan` |
| `update_recon_settings` | Change any settable field of an EXISTING project: the whole pipeline, the agent's settings and the engagement's limits. Validated, then capped at scan start rather than blocked. A compare-and-swap on `updatedAt`. | `recon:settings` |
| `create_project` | Open an engagement and fix its scope, atomically with the record of what authorized it. | `project:create` |
| `attach_engagement_authorization` | Record the scope document that permits this engagement. Append-only. | `engagement:authorize` |
| `list_engagement_authorizations` | The history of what authorized it, newest first. | `recon:read` |
| `preflight_scope_check` | Read-only proof that the configured pipeline fits the scope. RESOLVED values, not written ones. | `recon:read` |
| `kali_exec` | A shell in the sandbox: `bash -c`, full toolset, **no target check**. | `kali:exec` |
| `kali_output` | That command's output, paged from a byte cursor. | `kali:exec` |
| `kali_cancel` | Stop a command it started. | `kali:exec` |
| `list_findings` | Every finding, ranked when a triage run has produced a ranking and honest about it when not. | `recon:read` |
| `list_muted_findings` | The muted findings, whether a person muted them or a Mute Rule did (`muted_via`, and the rule's name). Hidden from every other tool here. | `triage:read` |
| `list_remediations` | What to fix, with CVSS, CVE/CWE/CAPEC, exploit and KEV flags. | `triage:read` |
| `get_project_activity` | Every scan in flight on this project, plus whether a start would be refused. | `recon:read` |
| `list_scan_versions` | Saved graph versions, with `pinned` and `hasSnapshot`. | `recon:read` |
| `compare_scan_versions` | What changed between two graph states. Counts and names only. | `recon:read` |
| `describe_recon_settings` | The reference manual for `update_recon_settings`: meanings, types, bounds. | `recon:read` |
| `list_recon_presets` | The built-in presets and the account's own, optionally with their values. Saved presets it cannot read are reported `unavailable`, never as none. | `recon:read` |
| `create_recon_preset` | Save a preset from explicit settings, a copy of another preset, or a capture of a project. Validated like a settings write; never carries scope, limits, credentials or uploads. | `preset:write` |
| `update_recon_preset` | Rename, re-describe, merge or remove keys in one of the account's presets. Built-ins are immutable. | `preset:write` |
| `delete_recon_preset` | Delete one of the account's presets. The audit row keeps its settings. | `preset:write` |
| `apply_recon_preset` | The form's "Load preset", server-side: REPLACES the configuration, with `dryRun`. Refused while anything reads or writes the graph and when the backends' defaults cannot be read. | `preset:apply` |
| `get_attack_surface_overview` | Hosts, services, web surface and findings by severity, in one query. | `recon:read` |
| `list_exploit_paths` | Technology + CVE pairs ranked by observed exploit, then CVSS. | `recon:read` |
| `get_blast_radius` | Technologies ranked by how much of the surface they touch. | `recon:read` |
| `list_graph_views` | Saved graph views, by name. Never their query text. | `recon:read` |
| `run_graph_view` | Run a saved view through the same guards as raw Cypher. | `recon:read` + `graph:cypher` |
| `queue_recon` | Queue a full recon for when the host has room. | `recon:queue` |
| `cancel_queued_scan` | Cancel a queued job, reading the update count so a lost race is not reported as success. | `recon:queue` |
| `get_scan_status` | The other six scanners' state, masked exactly as `get_recon_status` is. | `recon:read` |
| `loop_wait_step` | Agent in the Loop (§9): long-poll for the next step of the user's chat runs, or their status. | `agent:loop` |
| `loop_get_step` | A page of a step the caller holds, or the whole step again (`full`). | `agent:loop` |
| `loop_submit_step` | Answer a step (or decline it). RedAmon still applies every gate. | `agent:loop` |
| `set_finding_verdict` | Record a durable decision (Real raises the score, False positive, Reset of an MCP decision), rescored in the same transaction. Never a decision made in the app (`decided_in_app`, absent channel = app); refused on a muted finding, during an activation, and whenever the agent cannot acknowledge `layered_publish` (an older agent image enforces neither `decided_in_app` nor publish-time honouring). | `triage:write` |
| `get_finding_triage` | One finding's final score and the three layers behind it (rules, review, decision), detector, group, proof, run. Review text only with `includeQuotes`. | `triage:read` |
| `get_finding_evidence` | The normalised, secret-redacted evidence bundle the built-in reviewer reads, its `evidenceHash`, reviewability and the review contract. | `triage:read` |
| `submit_finding_review` | An external review: verdict, disputes and a multiplier, each quote-verified against the rebuilt bundle; RedAmon recomputes the score. Refused on a decided, proven (when lowering), unscored, resolved or changed-evidence finding. | `triage:review` |
| `get_triage_status` | Triage state (incl. `imported`), the live run's phase/progress/trigger, recent runs, the preflight, the MCP start allowance, decided-by counts, what a live run blocks. | `triage:read` |
| `start_triage_run` | Start a headless Priority Board run (`POST /triage/runs`). 30-minute cooldown and 12/day per project across tokens, 1,000-review clamp, `write` bucket. | `triage:run` |
| `stop_triage_run` | Stop a run before it publishes; refused while publishing. | `triage:run` |
| `mute_findings` | Mute 1-5000 findings with a reason. Never a proven or kept-visible one, never over an existing mute; no cap on a token's total; stamped `muted_channel=mcp` + token prefix. | `triage:mute` |
| `unmute_findings` | Unmute 1-5000 findings from the muted list, writing the Mute Rules exemption FIRST. A rule's mute only with `includeRuleMutes`, never during a recon scan. | `triage:mute` |
| `search_muted_findings` | Page every muted finding with the Muted Nodes filters (who muted, rule, token, text), with exact facets. The only source of a muted finding's id. | `triage:read` |
| `update_project_scope` | Change an existing project's target LISTS (batch hosts, GitHub org/repos, GVM strategy, supply-chain org/repo/ref/scope, and an IP project's hostname policy: `ipHostnameMode`, its include/exclude filters, passive expansion, the scan_all confirmation and the two caps). Guardrail on every listed host, scan root, registrable domain and hostname include entry, and the refusal names the host; a third-party widening (a host the old list did not admit, a hostname policy that scans more) needs an authorization record, and `scan_all` is refused on a third-party engagement outright. | `project:rescope` (+ `engagement:authorize` to pass `authorization`) |

**Deliberately not exposed:** the agent chat, partial recon, project
delete/import, secrets and LLM keys, re-pointing an existing project's target
domain, address list or targeting mode (only its target LISTS move, behind
`project:rescope`), the engagement RECORD (the client, the contacts, the dates, the
document), guardrails, **starting** a GVM / TruffleHog / supply-chain / AI
attack-surface scan, captured HTTP traffic, version activation or deletion,
Mute Rules (the rules, their presets, applying or arming them), setting a
finding's score, tier or factors directly, and any graph **write** other than a
verdict, a review, a triage run start or stop, and (behind `triage:mute`) a mute
or unmute.

Note the distinction the reads above draw: their FINDINGS are readable (a
finding is a finding whichever scanner wrote it), while **starting** those scans
is not. Muting and unmuting ARE exposed, but only behind their own opt-in
permission, `triage:mute`, and bounded in code rather than by the tool wording:
mute is the one action that makes a finding invisible to every other read here,
and the surface was originally built on "only a person mutes". §6 "Mute and
unmute over MCP" lists what replaces that guarantee. RedAmon's own AI still never
mutes. Mute Rules stay withheld: a rule is a bulk mute.

`kali_toolbox` serves the `kali_shell` `TOOL_REGISTRY` description verbatim -
the same bytes the in-app agent is prompted with. One source, no second copy: a
transcription would drift from the image the moment a tool is added, and a
catalogue that lies about what is installed is worse than none. All of it is
runnable, because `kali_exec` is a shell.

One correction is appended, and it is not a fork of the catalogue. The catalogue
is written FOR the in-app agent, which has dedicated tools (`execute_nmap`,
`execute_nuclei`, `execute_curl`) alongside `kali_shell`, so it ends by telling
the reader NOT to use the shell for those. An MCP caller has no dedicated tools:
`kali_exec` is the only way it runs anything, so read literally that line tells
it not to use the one tool it has. A short `NOTE FOR MCP CALLERS` after the
catalogue says so, and names the tools the advice steered it away from.

Served by the agent's `GET /kali/toolbox` (`require_master_internal_auth`). It
never calls the kali-sandbox, holds no `MCP_AUTH_TOKEN`, and takes no
`projectId`, so it answers even when the sandbox is down.

### 1.1 `kali_exec` IS `kali_shell`

**This is a shell, by decision.** `kali_exec` hands the command verbatim to
`kali_shell`, which is `subprocess.run(["bash", "-c", command])` on a container
with `NET_ADMIN`, `NET_RAW`, `seccomp:unconfined` and open egress. Pipelines,
redirection, substitution, loops and every installed binary all work. There is
no allowlist, no per-flag check and **no per-command target check**.

That is deliberate parity with the in-app agent, and the reasoning is worth
recording because an earlier version of this file argued the opposite at length.

**The in-app agent has no per-command admission either.** Its gates are a HUMAN
clicking the `DANGEROUS_TOOLS` confirmation (`REQUIRE_TOOL_CONFIRMATION`,
default on), an RoE check that matches tool NAMES and never reads a command
string, and a scope guardrail that runs once per session. None of those inspects
`kali_shell "nmap victim.tld"`. So a guard on the MCP path was not restoring
parity with the drawer - it was holding the MCP path to a standard the drawer
was never held to.

**What carries the weight instead is reachability.** Three independent switches,
each owned by a different decision-maker, and all three must be on:

| # | Switch | Who sets it | Default |
| --- | --- | --- | --- |
| 1 | `MCP_KALI_EXEC_ENABLED` | operator, per deployment | **on** |
| 2 | the `kali:exec` scope | user, password-confirmed at mint | **ticked** (every profile) |
| 3 | `project.mcpKaliExecEnabled` | a human in the project form | **on** (new projects) |

All three default on, so the sandbox works out of the box. Each can still be
turned off on its own, and the one decided per token is switch 2: unticking
`kali:exec` at mint is how a token is kept off the shell.

Switch 3 is `mcp: never` in the settings registry with the reason `escalation`,
so `update_recon_settings` cannot turn it on: a token can never grant itself
this. A token holding all three has a root shell in the sandbox,
and that is the intended contract.

**What this costs, stated plainly.** There is no server-side restraint on where a
command points. An agent granted `kali:exec` can reach any host the sandbox can,
including one this project is not for. The product's scope boundary is enforced
for `update_recon_settings` (§6) and for the recon pipeline; on this path it is
not enforced at all, and the surface says so in three places the agent actually
reads: the `kali_exec` tool description, the `kali:exec` consent copy, and the
Agent Onboarding pack. `onboarding.test.ts` fails if that phrasing regresses to
promising a check.

**What is still enforced**, because neither is about the command:

- The job id must be `uuid4().hex`, and the log path is composed server-side
  from `(project_id, job_id)`. `JobRegistry.status()` falls back to reading a
  `.meta.json` off disk, and `kali_exec` can write into that workspace, so
  trusting the `output_path` it carries was an arbitrary file read on the AGENT
  container - `/proc/self/environ`, and with it `INTERNAL_API_KEY` and the Neo4j
  password. Regression-tested in `LogPathTrustTests`.
- The endpoints require the MASTER internal key, not `SCANNER_API_KEY`, which
  every spawned scan container holds.
- A finished-but-failed job is readable, not a 404, and a run killed at the
  sandbox's 300s cap reports `status=failed` with the reason - never a clean
  exit 0.

## 2. Turning it on

It is **on by default** for a local install, so the MCP tools and Agent in the
Loop work out of the box: nothing answers until a person mints a token.
`./redamon.sh install` writes `MCP_SERVER_ENABLED=true`, and `./redamon.sh update`
turns an existing `MCP_SERVER_ENABLED=false` (written by earlier releases) on
**once**, recording it with `MCP_AND_LOOP_DEFAULT_ON_APPLIED=1`; a `false` set after
that is kept. A single-host deploy (`deploy.sh` marks its `.env` with `REDAMON_SINGLE_HOST_DEPLOY=true`;
`MCP_ALLOWED_ORIGIN` covers servers deployed before that mark)
keeps its own default, **off**, and `redamon.sh` never turns it on there.

```bash
# 1. In .env (redamon.sh writes the switch for you, on)
MCP_SERVER_ENABLED=true

# 2. Apply. The webapp has NO env_file, so this variable is read from the
#    compose `environment:` block - editing .env alone is not enough on its own,
#    but the block is already wired, so a normal restart picks it up.
docker compose up -d webapp
```

`redamon.sh` **refuses** to enable it while `INTERNAL_API_KEY` is unset or still
`changeme`. That is not a formality: the agent's auth fails *open* in that state
(`agentic/llm_guard.py` `_key_ok`) and the base compose publishes the agent on
`0.0.0.0:8090`, so the whole graph-isolation story would rest on a check that is
not running. Run `./redamon.sh install` to generate the secrets first.

### Knobs

All are optional; unset keeps the documented code default. All are wired into the
webapp's compose `environment:` block, because **the webapp has no `env_file`**
and a value set only in `.env` would be silently inert.

| Variable | Default | Meaning |
| --- | --- | --- |
| `MCP_SERVER_ENABLED` | `false` | The master switch. Off, every request gets a `404` whose error message says the server is disabled and names this variable - before any token is read, so it is no token oracle. |
| `MCP_KALI_EXEC_ENABLED` | `true` | `kali_exec` / `kali_output` / `kali_cancel`. Independent of the master switch on purpose; `false` withdraws the sandbox from every token, and removes `kali_toolbox`, `kali_exec`, `kali_output` and `kali_cancel` from `tools/list` (registration-time, like `MCP_DISABLED_TOOLS`) so no agent plans around them. |
| `MCP_RATE_EXEC_PER_MIN` | `20` | `kali_exec` calls per token per minute. Polling uses the read bucket. |
| `MCP_TOKEN_RETENTION_DAYS` | `90` | How long revoked/expired token rows are kept before pruning. |
| `MCP_RATE_READ_PER_MIN` | `120` | Cheap reads per token per minute. |
| `MCP_RATE_QUERY_PER_MIN` | `20` | `query_graph` calls per token per minute. |
| `MCP_RATE_WRITE_PER_MIN` | `10` | Settings, stop, verdict, preset and rescope calls per token per minute. |
| `MCP_RATE_MUTE_PER_MIN` | `200` | `mute_findings` and `unmute_findings` calls per token per minute, in their own bucket. One call names up to 5000 findings, so this is a runaway-loop ceiling, not a volume cap. |
| `MCP_RATE_START_PER_WINDOW` | `1` | Scan starts per project per window. |
| `MCP_RATE_START_WINDOW_MS` | `300000` | That window (5 minutes). |
| `MCP_RATE_COMPARE_PER_WINDOW` | `2` | `compare_scan_versions` calls per project per window. Its own bucket, not `query`: one call can gunzip and parse a whole stored graph. |
| `MCP_RATE_COMPARE_WINDOW_MS` | `300000` | That window (5 minutes). |
| `MCP_DISABLED_TOOLS` | (empty) | Comma-separated tool names to withdraw. They disappear from `tools/list` rather than refusing, so a client never plans around them. The per-tool alternative to taking the whole surface down; a name matching no tool is ignored. |
| `MCP_LLM_DAILY_BUDGET` | `200` | NL queries per token per day (they spend the owner's LLM key). |
| `AGENT_IN_THE_LOOP_ENABLED` | `true` | Agent in the Loop (§9). Written into `.env` by `redamon.sh` like `MCP_SERVER_ENABLED`, and on by default on a deploy too (inert there until the MCP server is on). Read by BOTH the webapp and the agent; off, the three `loop_*` tools are withdrawn from `tools/list` and the `loop/mcp` model is offered nowhere. Inert unless `MCP_SERVER_ENABLED` is on too. |
| `MCP_RATE_LOOP_PER_MIN` | `120` | `loop_*` calls per token per minute. One step costs two to four calls. |

> **The generated API reference describes a build, not a deployment.** It is
> rendered from the server's own `tools/list` with no tool withdrawn, so a
> deployment using `MCP_DISABLED_TOOLS` advertises fewer tools than the page
> lists. Ask the server itself if you need the authoritative set for one host.

Agent-side bounds (the agent **does** have an `env_file`, so `.env` reaches it):
`NEO4J_QUERY_TIMEOUT_MS` (120s), `GRAPH_EXEC_MAX_RECORDS` (1000),
`GRAPH_EXEC_MAX_BYTES` (2 MiB), `GRAPH_EXEC_MCP_CONCURRENCY` (5).

---

## 3. Minting a token

**Global Settings → MCP Server → New token.**

- **Minting is self-only**, judged on your real login identity. An admin viewing
  another user's settings sees the form disabled with a reason: a token minted
  that way would outlive the act-as session, need no further authentication, and
  be indistinguishable from the user's own calls. Admins *can* list, narrow and revoke;
  taking power away is a safe privilege, adding it is not.
- It asks for your **password again**. A stolen 7-day session cookie must not
  silently become a credential that outlives logout.
- **Permissions default to read-only.** Every write permission is opt-in, and
  each says what it allows. `recon:overwrite` says plainly that it permits
  discarding the current graph.
- **An Agent Profile picks the starting permission set** (§3.1). It is a label
  and a suggestion, never an authorization input.
- **With `RBAC_PERMISSIONS_ENABLED` on, you tick only what you may do yourself**
  (§6, "Your own permissions cap every token"): a scope whose RedAmon permission
  you lack is shown disabled, tagged "limited by your permissions" with the
  permission it needs, and the mint refuses it before asking for your password.
  Minting at all needs `self:mcp_tokens` (gone for everyone while
  `MCP_SERVER_ENABLED` is off).
- **`triage:write` is the verdict write**, and a verdict cannot be undone from
  this surface except by another verdict. It writes
  `triage_source = 'human'` deliberately: a third provenance value would make
  the finding prune-eligible on the next scan, let a later AI run overwrite the
  verdict, stop `likely_noise` producing a false-positive state, and render as
  "Not reviewed". The channel is recorded on `triage_verdict_channel` instead,
  and the actor on `triage_verdict_by`. It never mutes or unmutes, directly or
  indirectly (that is `triage:mute`), which is why **it is refused on a muted
  finding**: so `triage:write` alone can never release a rule mute.
  `triage_source = 'human'` is a Mute Rules guard: rules never mute a finding a
  person judged, so a verdict on a rule-muted finding (any status, `likely_noise`
  and `unreviewed` included) would release the mute at the next "apply to
  current graph", or the next scan that finds it again. That is an unmute by
  another name. The agent keys the refusal on the MCP channel (`source: "mcp"`
  sets `refuse_muted` on `set_human_verdict`). The check runs in the same Cypher
  statement as the write, AFTER taking the node's write lock: under read
  committed, a label read before the lock can see "not muted", wait on a
  mute's lock, and then write onto the node that mute just committed. The
  refusal covers a person's mute as well, and nothing is written. A verdict from
  the app is unaffected: the person clicking could unmute the finding anyway.
- **`triage:review` is a machine's reading, not a decision**, so it is split
  from `triage:write`. A review corrects the four factors with verified quotes
  and RedAmon computes the score (`combine_layers`); it is stamped
  `triage_ai_channel = 'mcp'` with the token prefix, is valid only while its
  `triage_ai_evidence_hash` equals the finding's `triage_evidence_hash`, is never
  re-reviewed by a run while valid, never overrides a person's decision, and its
  text never reaches `Remediation.solution`/`evidence` (so never CodeFix). An
  `mcp` false positive keeps its member in the fix group (P2).
- **`triage:run` starts and stops Priority Board runs.** Opt-in on `triage`
  only. MCP starts are spaced (`MCP_RUN_COOLDOWN_MS`, 30 min) and capped
  (`MCP_RUNS_PER_DAY`, 12) per project across every token, counted from
  `TriageRun.trigger = 'mcp'`; they spend the `write` bucket, not `start`, which
  is shared with `start_recon` and `queue_recon`. The review budget is clamped to
  1,000, and a start with no review model ranks rules-only.
- **`triage:mute` is separate from `triage:write`**: a verdict ranks a finding,
  a mute HIDES it from every read. It is opt-in, never auto-ticked by a profile
  (`NEVER_AUTO_TICKED`), offered only by `triage`, and adding it to a token is
  widening, so it asks for the password. What bounds it is in §6.
- **`recon:queue` is separate from `recon:scan`**, because a queued job
  dispatches LATER. `JobQueue` carries no token id and revoking a token writes
  only `revokedAt`, so work queued by a credential OUTLIVES that credential;
  only `cancel_queued_scan` or the Activity view stops it. The same missing
  column means a queued job appears in the operator's own queue attributed to
  them, with nothing marking it as an agent's.
- **`triage:read` is separate from `recon:read` on purpose**, and it is the one
  read permission that is not ticked by default. It unlocks the muted findings,
  whether a person suppressed them or a Mute Rule did (with who or which rule
  muted them, and why), and the remediation write-ups. Neither was reachable by any route before, so folding
  them into `recon:read` would have changed what every already-minted token can
  read, with no operator action and no visible change to its permission chips.
- **Expiry** defaults to 90 days. It is re-checked on *every call*, so expiry and
  revocation take effect mid-session rather than at the client's next reconnect.
- The token is shown **once**. Afterwards only its first 8 characters are ever
  displayed.

**Editing a token** (`PATCH /api/users/[id]/mcp-tokens/[tokenId]`) changes its
name, scopes and expiry (`expiry`: `30|60|90|365`, `"never"`, `"now"`, or a
`YYYY-MM-DD` date that lasts to the end of that day UTC). The hash and owner are
never mutable, and a revoked token can only be renamed. Edits are judged by
**direction**:

- **Narrowing** (drop a scope, earlier expiry, `"now"`, rename) keeps the admin
  bypass, like revoke.
- **Widening** (add a scope, later or no expiry, reviving an expired token) gets
  the mint's step-up: self-only on the real identity, password re-confirmed, and
  the same limiter key as minting, so the two share one attempt budget. Without
  this a stolen session cookie could upgrade an existing token into the
  credential it cannot mint. `isTokenWidening` in `webapp/src/lib/mcpAuth.ts` is
  the single rule, used by both the route and the tab.

Scopes and expiry are re-read on every MCP call, so an edit applies on the
agent's next call. Capability edits audit as `mcp-token.update` with
before/after values and `widened`.

**Any password change revokes every token** for that user, including an admin
reset (which needs no current password). A reset that left live programmatic
credentials behind would not actually lock the account.

---

### 3.1 Agent Profiles, and why they are safe

A token is minted FOR A JOB. `McpAccessToken.profile` records which, and the
registry lives in [`webapp/src/lib/mcp/profiles.ts`](../../webapp/src/lib/mcp/profiles.ts).

```prisma
/// NOT an authorization input. Scopes alone are enforced.
profile String?
```

Nullable, so every row minted before the field existed is valid and reads as
`custom`. An UNKNOWN profile is rejected at mint and at PATCH rather than
coerced, mirroring `validateScopes`: silently storing something the operator did
not ask for labels a credential as a job nobody chose.

**The field is never read by any authorization path.** Not `resolveMcpToken`,
not `requireScope`, not the rate limiter, not a tool body. `profiles.test.ts`
enforces this two ways: `mcpAuth.ts` must not contain the string `profile` at
all, and no other module under `src/lib/mcp/` may read `.profile` off a token or
context. A second, weaker authorization path is the one genuinely dangerous
thing this feature could have introduced, so the control is a grep rather than a
convention.

The profile is read in exactly one place on the request path,
[`instructions.ts`](../../webapp/src/lib/mcp/instructions.ts), to choose the
editorial slant of the connect-time onboarding string, and only on `initialize`.
That read selects `{ profile: true }` and nothing else, and any failure falls
back to `custom`: failing to personalise a paragraph must never fail a
connection.

**Profile → recommended scopes.** Every profile starts from `recon:read` and
`kali:exec` (the `exec` column below), and seven of the thirteen grant no recon
or finding write.

| Profile | Recommended | Opt-in (never auto-ticked) |
| --- | --- | --- |
| `bug_bounty` | read, exec, scan, triage:read, cypher | `project:create`, `engagement:authorize` |
| `pentest` | read, exec, scan, triage:read, cypher | `project:create`, `engagement:authorize` |
| `asm` | read, exec, scan, queue, triage:read | `project:create` |
| `vuln_mgmt` | read, exec, triage:read | - |
| `triage` | read, exec, triage:read, **triage:write**, **triage:review** | `triage:mute`, `triage:run` |
| `inventory` | read, exec, cypher | - |
| `compliance` | read, exec, triage:read | - |
| `ci_gating` | read, exec, queue, triage:read | - |
| `reporting` | read, exec, triage:read, cypher | - |
| `ma_risk` | read, exec, scan, triage:read, cypher | - |
| `threat_intel` | read, exec, triage:read, cypher | - |
| `soc` | read, exec, cypher | - |
| `research` | read, exec, scan, **settings**, triage:read, cypher | `recon:overwrite` |
| `custom` | read, exec | - |

The rules behind it, each asserted in `profiles.test.ts`:

1. **`recon:overwrite` is in NO profile's `recommendedScopes`.** It may appear
   only in `optInScopes`, which the form renders unchecked behind a danger
   callout: irreversible graph destruction must not arrive as a side effect of a
   dropdown. **`kali:exec` is the opposite, in EVERY profile's
   `recommendedScopes`** and in `DEFAULT_MCP_SCOPES`, which must equal what
   `custom` recommends so an untouched form never reads as hand-edited.
2. **`triage:write`, `triage:review` and `recon:settings` each go to exactly one profile.**
   **`triage:mute` goes to none as a recommendation**: it is in
   `NEVER_AUTO_TICKED` with `recon:overwrite`, and only `triage` offers it.
3. **Unattended profiles prefer `recon:queue`.** `asm` and `ci_gating` run with
   nobody watching, where a direct start just fails on a busy project.
4. **Read-only wherever the job allows it.**

**A profile switch is judged by the existing widening check.** Switching profile
in the UI re-ticks the boxes, and the resulting scope SET flows through
`isTokenWidening` exactly like a hand tick, so a profile-driven widen demands the
same password step-up. A profile change with no scope change grants nothing and
needs no step-up; it is also allowed on a revoked token, like a rename.

### 3.2 Agent Onboarding: generating the pack

[`onboarding.ts`](../../webapp/src/lib/mcp/onboarding.ts) renders the operator's
download, and [`instructions.ts`](../../webapp/src/lib/mcp/instructions.ts) the
connect-time string, from one source. Built like `apiReference.ts`: the
machine-readable half comes from the server's own `tools/list`, so it cannot
describe a tool differently from how the server serves it, and a tool withdrawn
by `MCP_DISABLED_TOOLS` is absent from the pack for free because it never
reaches the list.

**Two filters, deliberately separate:**

- the **scope filter** is hard. `canCall` renders a tool as available only when
  the token holds every required scope; everything else goes in the
  "cannot call" tail with the permission it needs. A conditional scope is
  reported as a withheld ARGUMENT, not a missing tool.
- the **profile filter** is editorial. It chooses which workflows and tone are
  emphasised, and nothing else.

The pack renders **profile ∩ scopes**, plus the cannot-do tail. A profile that
leans on a tool this token cannot reach names the missing PERMISSION, never the
tool, so the profile section can never promise a call that will be refused;
`onboarding.test.ts` asserts exactly that over every profile and several scope
sets.

The hand-written half lives in
[`playbook.ts`](../../webapp/src/lib/mcp/playbook.ts) as three registries, each
guarded by a coverage test: `CAPABILITY_AREAS` (every tool in exactly one area),
`ONBOARDING_PLAYBOOK` (one entry per tool) and `WORKFLOWS` (rendered only when
the token can call every tool they need).

**Adding a tool to the MCP server now also means adding its playbook entry and
filing it under a capability area.** The coverage test goes red in the same
commit otherwise, which is what makes "the pack covers the whole surface" a
guarantee rather than an intention.

Output is deterministic: no dates, and the version stamp is injected, so the
same `(profile, scopes, serverUrl, style, layout, client)` renders byte-identical bytes.

`client` (`claude_code`, the default, or `codex`) matters only when the token holds
`agent:loop`: the pack then adds the Agent in the Loop skill
([`loopSkill.ts`](../../webapp/src/lib/mcp/loopSkill.ts)) with that client's
frontmatter and connection template (`.mcp.json` and `.claude/settings.json`, or a
`config.toml` block). The route answers `409 loop_disabled` for such a pack while the
switch is off.

**Nothing user-specific may enter the output** - no token, no project name, no
target, no rules-of-engagement text - because a `SKILL.md` gets committed into a
repository. The route
(`POST /api/users/[id]/agent-onboarding`) is session-authed with
`requireUserAccess`, not bearer-authed, and it grants nothing: the scopes in its
body describe a document, no token is read and no row is written. The only
caller-controlled string that reaches the file is the server URL, and only its
ORIGIN survives, after an http/https check.

## 4. Connecting a client

The mint dialog renders this pre-filled, so it is copy-paste with no editing:

```json
{
  "mcpServers": {
    "redamon": {
      "url": "https://<redamon-host>/api/mcp-server",
      "headers": { "Authorization": "Bearer rdmn_mcp_<token>" }
    }
  }
}
```

Client support for a **static bearer header on a remote MCP server** varies and
changes, so this document does not assert a list. **Verify your client end to
end before relying on it.** Claude Code, for example:

```bash
claude mcp add --transport http redamon https://<host>/api/mcp-server \
  --header "Authorization: Bearer rdmn_mcp_<token>"
```

---

## 5. Behind nginx (single-host deploy)

The deploy template ships an **exact-match** location plus its own rate zone:

```nginx
limit_req_zone $binary_remote_addr zone=mcp:10m rate=10r/s;
location = /api/mcp-server { ... }
```

Two things worth knowing before you edit it:

- The `=` is load-bearing. A prefix block written `location /api/mcp-server/`
  does **not** match the endpoint URL `/api/mcp-server`; the request silently
  falls through to `location /api/` with the UI rate zone.
- A location carrying any `add_header` does **not** inherit the server-level
  ones, so HSTS/CSP and `Cache-Control` are re-emitted inside the block. Remove
  them and they are silently lost on this endpoint.

**`GATE_MODE=basic_auth` is mutually exclusive with bearer auth** — Basic and
Bearer cannot both travel in one `Authorization` header. Under that mode the
endpoint returns **403 by default**. To open it:

```bash
MCP_EDGE_ALLOW_BEARER=true   # emits `auth_basic off` for this one location
```

### The firewall is a separate gate, and it comes FIRST

This is the step people miss. `MCP_EDGE_ALLOW_BEARER` controls nginx. It does not
control the firewall, and the firewall runs first.

`ufw` scopes the app port to `OPERATOR_ALLOW_CIDRS` whenever that is set (the
recommended posture). It filters by PORT and **cannot see the URL path**, so an
agent connecting from anywhere else is dropped before nginx is consulted at all.
On such a host, flipping `MCP_EDGE_ALLOW_BEARER` alone changes nothing and the
client simply times out.

```bash
MCP_CLIENT_CIDRS=198.51.100.0/24   # where your AGENT connects from
```

That admits those sources to the port, and the exact-match nginx location then
narrows them to `/api/mcp-server` only: they do not gain the UI, the login page
or the agent WebSocket paths.

With no `MCP_CLIENT_CIDRS`, the location inherits the server's `allow`/`deny`
unchanged: the operator gate **and** the token. That is the right posture when
the agent runs on the operator's own network, and the wrong one for a remote
agent.

Three gates, all of which must admit the agent: the cloud Security Group, `ufw`,
then nginx. `./deploy.sh verify` probes the endpoint and tells the failure modes
apart (404 disabled, 401 working, 403 edge gate). Repeated 401s are banned by the
`redamon-mcp-auth` fail2ban jail.

### http-* modes are refused

`deploy.sh` will not enable MCP in an `http-*` ACCESS_MODE, and `ALLOW_INSECURE=1`
does not override it. The credential is a bearer token in a header: over plaintext
it crosses the wire on every call and, unlike a session cookie, it outlives the
session, so one capture is a durable credential.

In `https-ip` with a self-signed certificate most MCP clients reject the
connection. Use a real certificate (`TLS_MODE=provided`) or a domain.

---

## 6. The security model

### Identity

A token resolves to exactly **one** `userId`. There is no admin act-as for
tokens. Every project-scoped tool calls an ownership check first, and a project
that does not exist and one owned by someone else give the **same** answer, so a
token holder cannot enumerate other users' project ids.

That check takes the token's user id, never a browser session or the act-as
cookie. The browser-side *writers* that produce some of the rows those reads
return - saved graph views, remediations, queued jobs - answer 404 for another
user's project too: the shared browser guard has no log-only mode
(`ACCESS_ENFORCE` is ignored), so a different user cannot plant a row in this
project for a token to execute later through `run_graph_view`.

### Your own permissions cap every token

A token is a machine acting for one person, so it never does more than that
person could. With `RBAC_PERMISSIONS_ENABLED` on (identity switch on too), each
scope maps onto the RedAmon permissions whose registry entry names it
(`webapp/src/lib/mcp/scopePermissions.ts`; `recon:read` needs `recon:read` and
`graph:read`, `kali:exec` needs `agent:kali_exec`, and so on), and a scope needs
ALL of them; a scope no permission maps to is never usable.

- **Mint and widen.** A scope the owner cannot use is refused with 403
  `{error, code: 'forbidden', permission, scope}`, read fresh (a credential is
  being granted), after the body checks and before the password, so it spends
  no step-up attempt. A widening edit asks only about the scopes it adds;
  narrowing and revoking are never refused.
- **Every call.** `resolveMcpToken` keeps only the minted scopes the owner can
  use now (`usableScopes`): a set change, a deny override, an instance cap or a
  disabled account stops the token's next call, within the authorization cache
  bound, with the usual "This token is missing the required scope" error, and
  the scope comes back with the permission. The token row is never rewritten.
  If the owner's permissions cannot be read the call is refused (JSON-RPC
  -32603 / HTTP 500) and the webapp logs `[rbac] mcp_scope_cap_failed`; it never
  falls back to the minted scopes.
- **The token screen.** `GET /api/users/[id]/mcp-tokens` adds
  `ungrantableScopes` (scope -> the permissions it lacks) with the switch on;
  the scope checklist, the Agent Profile ticks and the onboarding pack skip
  those scopes.
- **No act-as.** A token's owner's own permissions decide, never an admin's
  who acts as them; minting stays self-only.

With the switch off nothing is read and the minted scopes are the usable ones,
as before.

### Shared projects reach a token only when it opts in

With project sharing in force (`RBAC_SHARING_ENABLED` and Root's
`sharingPolicy.enabled`), `McpAccessToken.includeSharedProjects` and
`projectAllowlist` decide whether a token also reaches the projects shared with
its user (step 4.10, SH-42). Every existing token keeps both at their defaults
(off, empty) and reaches only its owner's projects.

- **The check.** `mcpProjectAccess(token, projectId, needed)` / `assertMcpProjectAccess`
  (`webapp/src/lib/mcpAuth.ts`) ask `projectAccess()` for the token's user. The
  owner reaches every level. Anyone else's project is admitted only through a
  live share (`via: 'share'`; oversight and break-glass never reach a token),
  only when the token opted in, and only when its allowlist is empty or names
  the project. Then the share must meet the tool's level: `R` for the read
  tools, `R*` for raw Cypher (`query_graph` with `cypher`) and `run_graph_view`
  (an arbitrary answer can carry attack-chain step content, which is raw data),
  and the owner's for everything else, so every write, start, queue, Kali and
  loop tool stays the owner's until Phase 5. A level shortfall answers its own
  message (`McpLevelDenied`, audited `level_denied`); a project the token does
  not reach is still `Project not found`. A revoked or expired share fails the
  next call (nothing is cached).
- **The tenant.** Every graph, finding, mute and triage read passes the
  project's owner (the check's `userId`) to the agent, never the token's user,
  and the result check holds the rows to the owner.
- **What a reader does not get.** `query_graph` with `question` is refused (it
  spends the owner's provider key: the browser's `agent:assistants`, `W+A`);
  `get_recon_settings` drops the `share: secret` columns (the custom header
  lists); `preflight_scope_check` withholds the authorization record
  (`authorizationWithheld: true`; `engagement.hasAuthorization` still says one
  exists); `list_engagement_authorizations` stays the owner's, as the app's list
  asks `engagement:authorize` (`M`).
- **`list_projects`.** Owned projects, plus the live shares when the token
  opted in (narrowed by the allowlist), each row with `myAccess` while the
  sharing switch is on.
- **Mint and edit.** The token screen offers **Include projects shared with me**
  and the shared projects to limit it to, only while `/api/auth/me` reports
  sharing in force. Opting in, emptying the allowlist or naming another project
  is a widening (the mint's password, self-only); opting out or naming fewer
  narrows. With the switch off the routes neither read nor list the two fields.

### The route is bearer-only

It ignores the session cookie, `X-Internal-Key` and `X-Scanner-Key`:

- honouring the cookie would make this middleware-exempt, state-changing POST
  **CSRF-reachable** from a logged-in operator's browser;
- honouring the scanner key would let a leaked token — held by *every* spawned
  scan container, the least-trusted tier — authenticate to the control plane.

It also requires `Content-Type: application/json`, rejects a foreign `Origin`,
rejects JSON-RPC batches, caps the body at 1 MiB (sized for a 5000-finding
mute), and answers `GET`/`DELETE`
with 405.

### The settings surface

`PUT /api/projects/[id]` (the project form's save) writes every `Project`
column its body carries, and `Project` has over 700 scalar columns — so almost
anything that reaches it is written. Describing exclusions in prose is therefore
not a control. It strips only the row bookkeeping (`id`, the actor columns, the
version-activation lock) and the upload-managed columns their own endpoints
own, stamps `updatedById`, writes a `project.update` audit row (credentials by
name only), and, when the body carries the `updatedAt` the form loaded, writes
only while the row still has it: a form left open answers `409` instead of
reverting what an MCP agent changed meanwhile.

**The allowlist stopped being the control; validation at the point of use became
it.** The first version of this surface refused 586 of the 712 columns by name,
which was a crude proxy for "this value could be dangerous" and wrong in both
directions: it refused `nucleiTags`, a bug-class filter, while permitting
`takeoverRateLimit` to run at 500 rps past a 3 rps engagement ceiling.

Every parameter is now described once, in
[`recon_settings/registry.yaml`](../../recon_settings/registry.yaml), and each
one carries a bound or a named validator. Three dispositions decide what a token
may write:

| Disposition | Count | What it means |
| --- | --- | --- |
| `settable` | 703 | write at any time through `update_recon_settings` |
| `create_only` | 26 | the engagement scope: written once by `create_project`, refused by name by `update_recon_settings`; the 15 marked `rescope: true` (the target lists, below) move only through `update_project_scope` |
| `never` | 53 | not a pipeline parameter at all; refused with its class. 20 of these are the engagement RECORD (`engagement-record`); the record's uploaded RoE document and its parse are 5 more, `upload-managed` |

There used to be a fourth, `tighten_only`, holding the Rules of Engagement under
a write-time direction rule. It is deleted rather than migrated. The rule bought
the appearance of a guarantee and not the guarantee: five of the fields it
covered - the whole time window - accepted a WIDENING while reporting a
tightening, because `narrow` has no machine-checkable direction.

What replaced it is that the engagement splits in two. Its 14 LIMITS - the
rate ceiling, the never-touch hosts, the scanning window, the agent's denylists -
are ordinary `settable` fields in the `engagement_limits` group (whose 15th
field, `roeEnabled`, is derived from them and never written: `deny_reason: derived`), reachable from
the project form and from `update_recon_settings` alike, in either direction.
What makes them safe is that every one is ENFORCED at scan start whatever the
setting says. Its 25 RECORD columns - the client, the contacts, the dates,
the uploaded document - are `never`, with `deny_reason: engagement-record` (20)
or `upload-managed` (the document and its parse, 5): a
person writes them, a model reads them, nothing enforces them, and they carry a
third party's personal data.

A test walking `Prisma.ProjectScalarFieldEnum` fails until every column has an
entry, so a new Prisma field still fails the build until someone describes it —
but describing it is now writing what it means and what it accepts, rather than
deciding whether to refuse it.

The attack this still prevents:

```
update_recon_settings({targetDomain: "victim.com", targetGuardrailEnabled: false})
start_recon()
```

Both fields are `create_only`, so both are refused by name on a project that
already exists, with a pointer to `create_project`. Scope moves with a new
project, never with a new value on an old one. Unknown keys reject the **whole
call by name**, never silently.

**What replaced each deny class.** A rate above the engagement ceiling is
rewritten to the ceiling at scan start. A container image is not a setting at
all: every tool runs the image RedAmon ships. A custom header may not carry CR, LF,
`Host`, `Authorization`, `Cookie` or `Proxy-*`, each of which would change where
a request goes rather than annotate it. A wordlist or template path must resolve
inside this project's own directories, checked at the write AND again at
settings load, because a row also arrives through the webapp, an import and a
version restore.

That last one is not theoretical: ffuf sends each wordlist LINE as a URL path
and records which ones responded, so a wordlist aimed at a file inside the scan
container reflected its contents into the graph. The deny list was the only
thing in front of it.

**Written is not resolved.** `get_recon_settings` echoes what a caller wrote;
`preflight_scope_check` reports what the scan will actually run with. They
differ wherever the runtime corrects a value, and an agent that only read the
first would believe a rejected value was accepted.

### Prompt injection is expected

Everything the graph tools return is derived from scanner output about a live
target: page titles, headers, JS comments, certificate fields, findings text.
That data lands in the *external* agent's context, and that agent holds this
server's tools. Assume an instruction embedded in a page title reaches the model.

| What an injected instruction could try | What stops it |
| --- | --- |
| Redirect the platform at a new target | The target domain, the address list and the targeting mode are `create_only`: refused by name on an existing project, whatever the token holds. A different target means a different project. |
| Widen a third-party batch list or a scanner's target | Only `update_project_scope` moves a target list, behind `project:rescope`, which no profile ticks. Every batch root runs the permanent guardrail, and a widening of a `third_party` engagement is refused without an `authorization` record, which needs `engagement:authorize` too. The audit row records the digest. |
| Apply the loudest preset | Needs `preset:apply`. A preset never carries the engagement's limits, so the ceiling still rewrites every rate at scan start, and a `third_party` project cannot start without one. |
| Plant a stored instruction in the preset library | Needs `preset:write`, which only *Research and training* ticks. Values are bounded exactly as `recon:settings` bounds them; the preset drawer badges a preset an agent wrote last, with the token prefix; every write audits its before and after, and a delete keeps the settings. |
| Discard the victim's graph history | `mode:"overwrite"` needs `recon:overwrite`, off by default. |
| Launch a scan storm | Strict per-token/per-project start bucket + the orchestrator's one-scan-per-project rule. |
| Escalate scan aggression | Aggression is SETTABLE and CAPPED instead of refused. Every rate resolves to at most the engagement ceiling at scan start, and `roeForbiddenTools` / `roeForbiddenCategories` / `roeAllowDos` are checked in code before a tool executes. A `third_party` engagement cannot start without a ceiling at all. |
| Loosen the engagement to make room | Nothing REFUSES it, and that is deliberate: a write-time direction rule covered five fields it could not actually check. What stops it mattering is that the limits are applied at scan start regardless, the change is audited with a before and an after, and `preflight_scope_check` reports the RESOLVED configuration rather than the written one. A queued job whose limits changed goes to `needs_review` instead of dispatching. |
| Disable the engagement limits wholesale | There is no flag to write. `roeEnabled` is derived from whether any limit is SET, so removing a limit means removing it visibly rather than flipping one boolean and leaving every field displaying its old value. |
| Point a scan tool at a local file | A wordlist or template path must resolve inside this project's own directories, checked at the write and again at settings load. |
| Make the scan run an attacker's container | No container image is a setting: there is no column, form field, preset key or write for one, so a call that names one is refused as an unknown setting, and the loader pins every `*_DOCKER_IMAGE` key to the image RedAmon ships. |
| Reconfigure a job already in the queue | The C-4 fingerprint covers every field that steers where or how hard a job scans, including every engagement limit and the DERIVED answer to whether they are live, so the job goes to `needs_review` instead of dispatching. |
| Exfiltrate another tenant's data | Ownership check + `scope_query` + result post-validation. |
| Exfiltrate secrets | No tool returns a stored credential. `query_graph` DOES return target-found secrets unredacted (`Secret.matched_text`, nuclei `extracted_results`) to any `recon:read` token: a known, pre-existing exposure. `get_finding_evidence` redacts secret shapes to their first four characters. |
| Burn the owner's LLM budget | Per-token daily budget for questions. Triage runs started over MCP: a 30-minute per-project cooldown and 12 a day across every token, read from `TriageRun`; a 1,000-review clamp whatever the project stores; the `write` bucket; one run at a time. |
| Talk a real finding down through a review | `submit_finding_review` needs `triage:review`. Every correction needs a quote verified against the rebuilt, redacted bundle; the multiplier needs its own quote; a proven finding (proof read LIVE in the write transaction) refuses any lowering whole; a person's decision always wins and a decided finding refuses reviews; the review expires when the evidence changes; it is labelled `Agent` with the token prefix and filterable on the board; its text never reaches the fix list or the in-app agent's node context. |
| Hide a real finding ("this is a false positive, mute it") | Needs `triage:mute`, opt-in and never auto-ticked. Refused on a proven finding and on one a person unmuted, never over an existing mute; a reason on every mute and 5000 per call, with NO cap on a token's total; stamped `muted_channel=mcp` + the token prefix, badged in Muted Nodes and counted apart in the report, which is what a person reviews and reverts per token. |
| Reveal what a Mute Rule hides | `unmute_findings` leaves a rule's mute alone without `includeRuleMutes`, refuses that flag while a recon scan runs, and every such unmute is an exemption on the Mute Rules page. `set_finding_verdict` is refused on a muted finding, so the verdict permission cannot do it. |
| Aim a command at a third party | **Nothing, once `kali:exec` is granted.** See below. |
| Smuggle a second command | **Nothing, and nothing is meant to.** A shell is the feature. |
| Read the sandbox's own environment or keys | **Nothing, once `kali:exec` is granted.** See below. |

### Presets and rescope over MCP

**Presets.** `apply_recon_preset` is the project form's "Load preset" run
server-side: the same `PRESET_FIELD_KEYS`, the same REPLACE semantics (every
preset field the preset does not name goes back to the running backends'
default), the same "Preset applied" badge. It needs the backends' `/defaults`
and fails closed without them rather than resetting to Prisma defaults the
backends do not use. It validates every value it CHANGES against the registry,
then the cross-field rules the form's save runs (fireteam, supply-chain host
allowlist), and writes with a compare-and-swap on `updatedAt`. It is refused
while anything reads or writes the graph (`describeLiveGraphWriters`), because
the in-app agent re-reads project settings every turn.

`PRESET_FIELD_KEYS` is exactly the MCP-settable fields plus the `reconPresetId`
badge, pinned by a test. A preset once carried `mcpKaliExecEnabled` and
`updateGraphDb`, and because a preset resets what it does not name, applying
ANY preset in the UI re-enabled the MCP sandbox. Both are excluded now.

Presets are per user. A guessed id of another user's preset reads exactly like a
missing one, and apply needs the caller to own both the project and the preset.
The UI's own preset save and the project import now store only preset fields,
and reads, the export and apply project a stored blob down to them, so a legacy
preset carrying a target or a credential keeps it in the database.

**The badge.** `Project.loadedPreset` holds the preset's name, a fingerprint and
which preset it was (`presetId`, `source`). Renaming a user preset renames the
badge on the owner's projects that loaded it; deleting one, from the tool or
the preset drawer, clears it in the same transaction (`lib/reconPresets/badges.ts`,
a compare-and-swap per project). Editing a preset's values leaves the badge: it
says the project still holds what loading that preset produced. A badge written
before it carried an id keeps its name, since a name can also be a built-in's.
The fingerprint is `v2:` plus a digest of the preset fields NOT at their Prisma
default, so a column added later reaches every row at its default and hides no
badge. The unversioned digests written before (over the field set before and
after `mcpKaliExecEnabled` and `updateGraphDb` left presets) are still accepted:
that is the backfill, with no migration step to run.

**Rescope.** `update_project_scope` reopens the `create_only` fields the
registry marks `rescope: true`, which are the target lists the project form
already lets a person edit after creation: a batch project's host list, the
other scanners' targets (GitHub, GVM, supply chain) and an IP project's hostname
policy (`ipHostname*`: the mode, the include/exclude filters, passive expansion,
the scan_all confirmation and the two caps). The target domain, the address
list, the targeting mode, ownership verification and the target guardrail stay
refused whatever the token holds.

A batch that gains a host or wildcard entry, or a hostname policy that widens (a
mode that scans more names, an include entry added, an exclude entry removed,
passive expansion turned on, a cap raised; `ip_only` -> `record_only` is not
one), pauses every enabled `ScanSchedule` of the project in the same transaction
(`pausedSchedules` in the result, `pausedScheduleIds` in the audit). A scheduled
run is a full recon that nobody watches start, so it must not be the first thing
to reach a host an agent added; a person resumes the schedules in the Scans tab.
Only this MCP path pauses: a widening saved from the project form shows a
warning counting the enabled schedules and pauses nothing (decision D-24). A
narrowing of the hostname policy returns `hostnamePolicyMarked` instead. A
narrowing, the GitHub and supply-chain targets (no scheduled run reads them),
`apply_recon_preset` and `update_recon_settings` pause nothing and only report
`affectedSchedules`: those change how a run scans, capped by the engagement's
limits at start, not what it reaches.

**A stale agent flag.** `Conversation.agentRunning` is set and cleared by
fire-and-forget PATCHes, so an agent restarted mid-run left it true and every
busy check (apply, rescope, activation, the job-queue dispatcher,
`get_project_activity`) read the project as busy for good. `lib/agentSessions.ts`
asks the agent (`GET /agent-sessions/live?project_id=`, backed by
`WebSocketManager._active_tasks`) whenever a flag is set, and clears the flags
the agent does not hold with a compare-and-swap on the row's `updatedAt`. There
is no time-to-live, because a run lasts hours. An agent that cannot answer
leaves a set flag counting as a running session: fail closed.
The endpoint takes the MASTER internal key only (`require_master_internal_auth`):
the kali sandbox faces the target, and a live session id is all the
unauthenticated `/agent-session/stop` needs.

**Residual, stated plainly.** A token holding both `project:rescope` and
`engagement:authorize` can record an authorization for any document digest and
widen a third-party engagement with it. That claim is attributable (the token id
is on the record), not verifiable.

**Both directions of the stale-form problem.** Every MCP write is a
compare-and-swap. The project form's full save now sends back the `updatedAt` it
loaded, so a form left open answers `409` instead of reverting what an agent
changed meanwhile.

### Mute and unmute over MCP

The surface was built on "only a person mutes or unmutes": that is what bounded
a prompt injection to "mislabel a verdict a human can overrule". `mute_findings`
and `unmute_findings` replace that guarantee with controls enforced in code
(`webapp/src/lib/mcp/muteTools.ts`, `mute_findings_delegated` and
`resolve_muted` in `graph_db/mixins/recon/triage_mixin.py`, the `mute_many` /
`resolve_muted` ops at `/graph/triage`):

1. **Opt-in scope.** `triage:mute`, never auto-ticked, widening on edit.
2. **Evidence guard.** A finding that is `confirmed`, carries a `triage_proof`,
   or has a `ChainFinding-[:CONFIRMS]` edge is refused (`proven`), checked in the
   write under the node's lock.
3. **A person's unmute stands.** A finding with a `NodeFilterExemption` is
   refused (`kept_visible`). The pairs travel to the agent, which refuses the op
   if they are absent rather than reading "none".
4. **No overwrite, on any path.** The delegated mute never touches an
   already-muted node; the UI's `mute_finding` is a no-op on one; the agent
   refuses a `muted_by` starting `rule:` on every mute op, so no master-key
   caller can forge a rule mute (which the prune would delete).
5. **Reason required** (3-500 characters), stored on the node and in the audit.
6. **Rule mutes need `includeRuleMutes`** to unmute, refused while a recon scan
   runs (the scan-end sweep is not a `NodeFilterRun`, so only
   `describeScanWriters` sees it).
7. **Blast radius.** 5000 mutes / 5000 unmutes per call and the `mute` bucket
   (`MCP_RATE_MUTE_PER_MIN`, 200 calls a minute per token). Nothing caps a
   token's total, so the bound on an injected agent is item 8: every mute it
   made is listed per token and reverted in one go.
8. **Provenance, written AND read.** `muted_by` stays the owner (it carries
   their authority, and the prune / sweep / partial-recon seeding treat it as a
   person's), plus `muted_channel='mcp'` and `muted_token=<prefix>`. Every
   unmute removes them and every other mute clears them. Muted Nodes, the MCP
   listings and the report are three-valued (person / mcp / rule).
9. **Busy checks fail closed.** Activation before and after the write (a lock
   read that throws counts as busy), an exemption read that fails is busy, and
   the apply or scan check runs before and after the unmute's exemption write.
   The in-app mute and unmute routes answer 409 during an activation too.
10. **An unknown outcome is said out loud.** A lost answer is
    `mute_outcome_unknown` / `unmute_outcome_unknown`; the unmute writes its
    exemptions first, so a lost answer converges on its own.
11. **Audited on both sides**: `muted_nodes.muted` / `muted_nodes.unmuted`
    (source `mcp`, token id and prefix, items, reason), the handler's
    `mcp.<tool>` row, and a `log_event` per item in the agent.
12. **Emergency lever**: `MCP_DISABLED_TOOLS=mute_findings,unmute_findings`.

The prune and the scanner clears also take the node lock before reading
`:Muted`, so a mute that commits mid-statement is kept rather than deleted with
the node. `tooling/scripts/mute_provenance_cleanup.py` strips leftover
provenance from unmuted findings after a rollback and roll-forward.

### The `kali:exec` residual, stated plainly

The three rows above used to claim a per-host scope check, an allowlist that
admitted no interpreter, and path confinement. **None of those exist any more.**
`kali_exec` is `bash -c` in the sandbox (§1.1), so an agent holding that scope
can run any installed binary against any host the sandbox can reach, use
pipelines and redirection freely, and read the sandbox's own process
environment.

That environment is not empty. At the time of writing the kali-sandbox
container carries `SCANNER_API_KEY`, `MCP_AUTH_TOKEN` and `TUNNEL_AUTH_TOKEN`,
so `env` is a credential read. `SCANNER_API_KEY` is the one to weigh: this route
deliberately refuses `X-Scanner-Key` as an inbound credential precisely because
the scanner tier is the least trusted, and an agent that can read it out of the
sandbox has recovered what the route declined to accept.

Two consequences worth stating rather than leaving to inference:

- **On a cloud deploy the instance metadata endpoint is reachable**
  (`169.254.169.254`), which on AWS returns the instance role's credentials.
  Nothing on this path refuses it.
- **Scope is the operator's judgement, not the code's.** The containment for
  `kali:exec` is entirely in who keeps the scope: it is ticked by default, also
  needs `MCP_KALI_EXEC_ENABLED` on the deployment AND the per-project toggle
  (both on by default), and every call is audited. With no refusal path left, **the audit row is the only record
  of what an agent did with the shell**, which makes it more load-bearing than
  when a guard existed.

Grant `kali:exec` only to an agent you would trust with a terminal on that box,
and prefer a deployment where the sandbox holds no credential you would mind
losing.

The other residual: a compromised external agent can do, within one user's own
projects, whatever that user's token already permits. That is inherent to
delegating a credential, and is why the default token is read-only.

### Result post-validation

Every node and relationship returned by a graph tool is re-checked against the
caller's tenant **on the way out**, and a violation drops the *whole* response
and writes an error-level audit record. This is defence in depth, not the primary
control — `scope_query` scopes the query server-side — but that filter has failed
once already (an unlabelled `MATCH (n)` once bypassed it), and on an
internet-reachable surface the same regression would be a *remote* cross-tenant
breach. Scalar projections carry no tenant keys to check; that residual is
accepted and bounded by `scope_query` alone.

---

## 7. Audit

Every call writes an `AuditLog` row: `mcp.<tool>`, the actor, the project, and
the token id and prefix. **Failures are audited too** — invalid, expired and
revoked token presentations (by prefix, never the token), scope denials,
ownership 404s and every post-validation violation — because that is the only way
a token brute force or a replayed revoked token becomes visible.

`submit_finding_review` also writes `triage.review`: the finding, its verdict, the
disputed fact NAMES, the multiplier, the score before and after, the token id and
prefix, and a SHA-256 of the review's text for forensic matching. The quotes, the
why and the fix lever are in `UNAUDITED_ARGS` and never reach an audit row. A run
writes `triage.start` (trigger, token id, effective review budget and model) and
`triage.finish`, or `triage.finish.late` when it reports after being declared lost.

A mute or unmute over MCP also writes `muted_nodes.muted` /
`muted_nodes.unmuted` with `source = 'mcp'`, the token id and prefix, every item
and its outcome, and the reason; `outcome: 'unknown'` records a lost answer.

The preset and rescope tools write their own rows with a before and an after:
`mcp.create_recon_preset`, `mcp.update_recon_preset`, `mcp.delete_recon_preset`
(which keeps the deleted settings), `mcp.apply_recon_preset` and
`mcp.update_project_scope` (with the authorization digest and whether the Domain
node was seeded). A refused settings write records the rejected key, a registry
key or `<unknown>`, never caller text. The project form's save writes
`project.update` with `source = 'ui'`, so a person reverting an agent's change is
reconstructible too; credentials are recorded by name only.

A `start_recon` also produces the normal `ScanJob` history row with
`initiatedByUserId` set to the token owner, and the audit record carries the
`scanJobId` so a run traces back to a token.

There is **no audit-log viewer in the product**: reconstruction is a SQL query
against `audit_log`. Known and accepted; a minimal admin view is a follow-up.

---

## 8. Operational notes

- **Settings apply to the NEXT scan.** Recon reads its settings once, at
  container spawn, so `update_recon_settings` refuses while a scan is writing the
  graph rather than accepting a write that would do nothing.
- **`start_recon` is stricter than the button.** It also refuses while a human is
  mid-session with the in-app agent or a triage run. Those are excluded from the
  normal check because a person running both is normal *and can see both*; an
  unattended external caller cannot, and a full scan would wipe the graph
  underneath them.
- **`mode:"new"` consumes a retention slot.** Old unpinned versions are trimmed
  past `SCAN_VERSION_RETENTION_KEEP` (default 20).
- **A dependency failure is never an empty result.** An unreachable orchestrator
  reports "status unknown", never "not running"; a graph failure never returns an
  empty summary. Conflating the two produces a false negative in a security tool.

---

## 9. Agent in the Loop

With `AGENT_IN_THE_LOOP_ENABLED=true`, a person may pick **Agent in the Loop**
(`loop/mcp`) as a project's agent model. Every model call of a chat run on that
project then becomes a **step** that the person's own MCP client (Claude Code,
Codex) answers through the three `loop_*` tools. RedAmon keeps the loop: state,
prompts, tools, the Rules of Engagement and phase gates, approvals, persistence
and the UI. The setup for each client is the wiki page
[Agent-in-the-Loop](https://github.com/samugit83/redamon/wiki/Agent-in-the-Loop);
the code and its invariants are in `agentic/agent_in_the_loop/` and the
`agent-in-the-loop` skill.

**How a step travels.** The agent's `LoopChatModel` (the session's `current_llm`)
opens a step in an in-memory broker and awaits its answer. The webapp tools call
the agent's master-key `/loop/steps/{wait,get,answer}` routes with the token's
user id, the token id, an optional client-chosen `driver` name, and the ids of
the user's projects that a loop run can be in NOW: on a loop model, or with a chat
running (the broker serves only those: a deleted or transferred project's steps
never reach a driver). Leases (90 s), deadlines (60 min from the step's opening),
a no-driver rule (30 min with no driver call that could serve that chat ends the
run, final report included, and frees the project lock; a driver scoped to one chat
is no presence for the others, and a claim whose lease ran out counts as unserved),
40 000-character pages and per-driver dedup of
unchanged prompt parts keep it bounded. A step's pages come from one rendering that
stays fixed for that client until the step closes, so cursors always line up; a
part counts as delivered only once the client asks for a later page or answers,
and it is sent in full again every 10 steps. `contractVersion` (2) marks the
step shape.

**A driver that goes quiet.** An interactive client makes no call while its
person talks to it, and only calls count as presence, so the no-driver rule is
sized for that pause and both sides see it. Every step carries
`runEndsIfSilentSeconds` (the no-driver grace, or the time to the step's
deadline if nearer), and the skill pack tells the driver never to end its turn
while a run is live. In the drawer, a lapsed claim shows as open, and a
`loop_status` frame with no driver connected carries `noDriverEndsInSeconds`, which
the drawer turns into the clock time the run ends. `step_closed` on a step the
driver never answered means the run gave up on it. When the run does end, the
report node writes a fallback from state alone (the last Fireteam wave, the
session's findings, how to resume), and the session list's hint tells the
driver that the person resumes by typing continue in the same chat.

**The new trust boundary.** An external process now decides the agent's next
action, and it reads target-controlled text at every step. The controls:

- **The token rule.** A token holding `agent:loop` may hold no other `write` or
  `read-write` scope (computed from the scope copy, `loopTokenProblem`); the loop
  tools refuse a wider token (`loop_token_too_broad`), and the token form and the
  onboarding modal warn before minting one. Injected text cannot reach a scan,
  a write or the shell over MCP through the driver.
- **Only a person approves.** No MCP tool answers a phase approval, a question,
  a dangerous-tool confirmation or a Fireteam escalation.
- **Dangerous tools follow the project's `REQUIRE_TOOL_CONFIRMATION`**, as in a
  provider run (default on). The owner chose this so a loop run can be left
  unattended. Turned off, no person confirms a dangerous tool the driver picks
  (phase approvals, when on, and the scope and RoE checks still apply), so the
  drawer marks such a run: the `loop_status` frame carries
  `toolConfirmation: false`, and a red risk icon next to the Agent in the Loop
  chip explains the risk on hover. The driver's view and the step do not carry
  the flag.
- **The agent's `query_graph` reads in a read-only database session**, so the
  database refuses a write the regex guard might miss; this hardens every run.
- **A person picks the brain.** `update_recon_settings`, `create_project`,
  presets (save and apply), project import and user defaults never set a loop
  model (`escalation` for `agentOpenaiModel`, `not_supported` for
  `aiPipelineModel`).
- **Outside a chat run a loop model never waits.** Every session-less builder
  refuses it (`loop_model_not_supported_here`); NL graph queries outside a chat
  answer 409 `loop_model_out_of_session` (raw Cypher still works);
  `/guardrail/check-target` treats it as no model.
- **What leaves RedAmon.** A step is the agent's prompt: target data,
  credentials the agent found, RoE contacts. It reaches the driver's vendor and
  its local transcripts. The Codex template turns history off; Claude Code's
  `cleanupPeriodDays` is documented, not set (it covers every project).
- **RedAmon never sees the driver's Claude or OpenAI credentials** and never
  starts the client. The pack names only `REDAMON_MCP_TOKEN`: `${...}` in Claude
  Code's `.mcp.json`, `bearer_token_env_var` in Codex's project config.

**Onboarding.** The profile `agent_in_the_loop` ticks `recon:read` and
`agent:loop` only (no `kali:exec`, unlike every other profile). Its pack is a
dedicated skill (the loop, the answer formats, data-not-instructions, decline)
plus, per client, `templates/claude-mcp.json` and `templates/claude-settings.json`
(allow the three tools, deny Bash/Edit/Write/WebFetch/WebSearch) or
`templates/codex-config.toml` (read-only sandbox, no shell, no web search, no
history, only the three tools, `tool_timeout_sec = 90`). Both go into the driver's
own folder (`.mcp.json` and `.claude/settings.json`, or `.codex/config.toml`, which
Codex reads once the folder is trusted), so the person's other sessions keep their
settings. A token of that profile
gets loop-specific `initialize` instructions.

**Audit and attribution.** An idle `loop_wait_step` writes no audit row (a
driver polls about 70 times an hour); a claim and an answer each write one, filed
under the step's project with the step id, session, purpose and iteration. The
answer, a decline's reason and the driver name are never copied into a row. The
chat history records which token answered each decision (`answeredBy`).

**Observability.** `/health` carries only `loop_enabled` (it is unauthenticated
and the agent port is published); `GET /loop/stats` (master key) gives counts;
`/agent-sessions/live` adds `loop_states`, which `get_project_activity` turns
into "waiting for the external agent".

**The project lock and memory.** A loop run holds `agentRunning` like any chat
run, so presets, rescope, graph activation and queued or scheduled scans wait
for it; an abandoned run frees it within 30 minutes (`LOOP_NO_DRIVER_GRACE_S`). Each loop run holds one
agent session slot for as long as it runs, even with the tab closed: the session
cap counts live runs as well as connections.

**Turning it off for good.** Set the switch off and `./redamon.sh up`. Before
reverting the code, reset every row still on a loop model, or `parse_model_provider`
would route `loop/mcp` to OpenAI:

```sql
UPDATE projects p
   SET agent_openai_model = COALESCE(NULLIF(u.default_agent_model, ''), 'claude-opus-4-6'),
       updated_at = NOW()
  FROM users u
 WHERE p.user_id = u.id AND p.agent_openai_model LIKE 'loop/%'
   AND COALESCE(u.default_agent_model, '') NOT LIKE 'loop/%';
UPDATE projects SET agent_openai_model = 'claude-opus-4-6', updated_at = NOW()
 WHERE agent_openai_model LIKE 'loop/%';
UPDATE users SET default_agent_model = NULL WHERE default_agent_model LIKE 'loop/%';
```

---

## 10. Related

- [README.MCP.md](README.MCP.md) — the outbound direction (system MCP servers + MCP Tool Plugins)
- [README.GRAPH_DB.md](README.GRAPH_DB.md) — the attack-surface graph
- [graph_db/schema_sections.md](../../graph_db/schema_sections.md) — the node labels and relationships `graph_schema` serves
- [GRAPH.SCHEMA.md](GRAPH.SCHEMA.md) — why the graph is shaped this way (lists no labels)
- [MCP-Server wiki page](../../redamon.wiki/MCP-Server.md) — the operator's view, including the Agent Profile table

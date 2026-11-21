# Kali Sandboxes: One per Person, Started on Demand

RedAmon runs its offensive tools (network recon, nuclei, Metasploit, nmap,
Playwright, Hydra, the terminal, tunnels) inside a container built from the Kali
image. Until now there has been one such container, `redamon-kali`, shared by
everybody. This document describes its replacement: each person who reaches the
Kali tools gets their own container, started by the recon orchestrator on first
need and stopped when unused.

A **sandbox** is one of those containers. It mounts only the project folders its
person may run the agent on, has its own random tokens, its own Metasploit
console and session manager, its own limits, and its own network, to which only
the agent and the capture proxy are attached. Removing the container at every stop
wipes everything a shell wrote outside the project folders and the person's output
folder.

> **Status.** Per-user sandboxes are being built behind a switch,
> `KALI_SANDBOX_MODE`, whose default is `shared`: every Kali call still goes to the
> shared `redamon-kali` container. The parts below land one by one and are
> inert until the default flips to `per_user`; after that the switch and the
> shared container are removed.

## Table of Contents

1. [The contract](#1-the-contract)
2. [How it works](#2-how-it-works)
3. [The switch](#3-the-switch)
4. [Names, labels and keys](#4-names-labels-and-keys)
5. [The mount plan](#5-the-mount-plan)
6. [The container](#6-the-container)
7. [The network](#7-the-network)
8. [Memory admission](#8-memory-admission)
9. [The lifecycle](#9-the-lifecycle)
10. [Leases](#10-leases)
11. [The orchestrator API](#11-the-orchestrator-api)
12. [The webapp gateway](#12-the-webapp-gateway)
13. [The agent](#13-the-agent)
14. [Events and messages](#14-events-and-messages)
15. [Environment variables](#15-environment-variables)
16. [Timings](#16-timings)
17. [Tunnels and reverse shells](#17-tunnels-and-reverse-shells)
18. [Keeping the tools current](#18-keeping-the-tools-current)
19. [Roll-back](#19-roll-back)

---

## 1. The contract

The code is the contract; this page explains it. Every name, value and pure rule
lives in three copies:

| File | Read by |
| :--- | :------ |
| `recon_orchestrator/sandbox_contract.py` | the orchestrator, which starts, stops and adopts sandboxes |
| `agentic/sandbox_contract.py` | the agent, which routes each Kali call to its person's sandbox |
| `webapp/src/lib/sandbox/contract.ts` | the webapp, which decides who may have a sandbox and with which projects |

The two Python files are byte-identical. `tests/test_sandbox_contract.py` fails when
they differ by one byte, when a TypeScript constant is missing or differs from the
Python value, and when a pure rule (the mount plan, the keys, the environment, the
subnet pick, the variable parsers) stops keeping persons apart. Change the three
copies together, and this page with them.

The Python contract uses the standard library only and imports nothing else from
RedAmon, so both services and the tests load it by path.

## 2. How it works

```
browser ──ws-ticket mint──► webapp ── touch (no lease, silent) ─────────────┐
                                                                             ▼
agent (run of person P) ─► router.acquire(P) ─► webapp gateway ─► orchestrator
   │   per-person MCP client        │  POST /api/internal/      re-checks P,   ensure(P, folders)
   │   (5 SSE servers, P's token)   │  agent/sandbox/ensure     computes folders  [lock per P]
   │                                │                                          ├ running  → address, token
   │                                │                                          ├ starting → wait same start
   │                                │                                          ├ stopping → wait, start new
   │                                │                                          ├ no memory→ 409 governor payload
   │                                │                                          └ none     → admit, network
   │                                │                                            redamon-sbx-<key> (/28),
   │◄──────── address, tokens ──────┘                                            container redamon-kali-<key>-<inst>,
   │                                                                             attach agent (alias agent),
   ▼                                                                             attach capture proxy, wait healthy
redamon-kali-<key>-<inst>  ── mounts: /workspace/<allowed project ids>, /opt/output = mcp/output/users/<key>,
                              /opt/mcp_servers (ro), /opt/graph_db (ro), /opt/nuclei-templates (ro),
                              /root/nuclei-templates = templates volume (ro), /osv-db (ro)
                           ── networks: redamon-sbx-<key> only (agent, capture proxy, NAT egress)
```

- Every unit of work (a chat run, an MCP `kali_exec` job, a terminal, a triage
  refresh, a Tradecraft fetch) acquires the sandbox once and holds a **lease**,
  renewed every 30 s and released at its end.
- The orchestrator stops an instance when no lease is held and it has been unused
  for `KALI_SANDBOX_IDLE_MINUTES` (20 by default), or when only a `hold` lease (live
  Metasploit sessions, an active tunnel) is held and it has been unused for 8 hours
  (with a warning from the seventh).
- Losing access to a project stops at once every instance that mounts it; a newly
  needed project starts a replacement instance while the old one drains. Deleting a
  project stops every instance that mounts it before its folder is purged.
- Work an admin does while acting as a person runs in that person's separate
  `act_as` view, which mounts only what acting access allows (the person's own
  projects, never the projects shared with them).
- The agent and the capture proxy forward no packets between their networks, the
  proxy refuses the sandbox address pool, and the orchestrator re-attaches either
  guest when it is missing from a live sandbox network (a recreated agent container
  is a new container).
- In `shared` mode the orchestrator answers `{"mode": "shared"}` and every caller
  uses the shared container and its fixed addresses.

Words used below: a **person** is who does the work (a WebSocket ticket's `sub`, an
MCP token's owner); the **tenant** is the project's owner, whose graph, traffic and
keys a request touches. Sandboxes are routed by person; everything else keeps
routing by tenant. An **instance** is one sandbox container: a person normally has
one per view, two during a rolling replacement.

## 3. The switch

| Name | Value |
| :--- | :---- |
| `KALI_SANDBOX_MODE` | `shared` or `per_user`; read by the orchestrator only |
| Default | `shared` until the default flips; then `per_user` |
| Parsing | the value, trimmed and lower-cased, when it is one of the two modes; anything else is the default |

The agent learns the mode from each `ensure` answer and remembers the last one. It
falls back to its own copy of the default only while the webapp gateway cannot be
reached and no answer has arrived since the agent started. Once it has seen
`per_user`, an unreachable gateway is an error (`SandboxUnavailable("error")`),
never a call to the shared container.

The switch is temporary: once per-user mode is the default and has been verified,
the shared code paths, the switch and the shared container are removed.

## 4. Names, labels and keys

| Name | Value |
| :--- | :---- |
| Image | `redamon-kali-sandbox:latest` |
| Views | `own` (the person's own work), `act_as` (an admin acting as the person) |
| Key of a view | first 16 hex characters of the SHA-256 of the user id (`own`) or of `act_as:` + the user id (`act_as`). A user id cannot contain `:`, so the two views of different persons never share a key |
| Network | `redamon-sbx-<key>` |
| Instance | 6 random hex characters, new for every start |
| Container | `redamon-kali-<key>-<instance>`, hostname `kali-sandbox` |
| Governor reservation | `kali_sandbox:<user id>:<instance>` |
| Valid user id | `^[A-Za-z0-9_-]{1,64}$`, and not `ensure`, `mode`, `stop-all` or `stop-project` (the single-segment routes under `/sandboxes/`) |
| Valid project id | `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$` (no dot at all), and not a Windows device name (`CON`, `NUL`, `COM1`, ...) |

Both id rules accept every id the database holds: Prisma's `cuid()` default for
users and projects, the 20-32 lower-case characters a client may choose for a new
project, and the fixed ids of the test seeds. They are matched as whole strings
over ASCII ranges, so a trailing newline, whitespace, a Unicode look-alike or a
percent-encoded dot is refused.

Labels of a sandbox container:

| Label | Value |
| :---- | :---- |
| `redamon.sandbox` | `1` |
| `redamon.sandbox.user` | the user id (labels are not visible inside the container) |
| `redamon.sandbox.view` | `own` or `act_as` |
| `redamon.sandbox.key` | the view's key |
| `redamon.sandbox.instance` | the instance |
| `redamon.sandbox.projects` | first 16 hex of the SHA-256 of the sorted, de-duplicated project ids joined by a newline |
| `redamon.sandbox.created` | epoch seconds |
| `redamon.sandbox.port` | the pool port, or empty |
| `redamon.sandbox.servers` | first 16 hex of the SHA-256 over the sorted relative paths, sizes and modification times of the MCP server files (bytecode and dot folders skipped), so a running sandbox notices new server code |
| `redamon.sandbox.contract` | `1` |

The nuclei templates refresher carries `redamon.sandbox=1` and
`redamon.sandbox.role=templates`, and no user label. Sandbox networks carry the
first four labels.

## 5. The mount plan

The mount plan is a pure function of the person, the view and the allowed project
list. The orchestrator maps each kind to a host folder found in its own mount table
and joins the relative part with `join_host_path`
(`recon_orchestrator/container_manager.py`, safe for POSIX and Windows host paths).

| Kind | Relative part | Target in the sandbox | Read-only | Host base (orchestrator mount) |
| :--- | :------------ | :-------------------- | :-------- | :----------------------------- |
| `workspace` | `<projectId>`, one per allowed project, sorted and de-duplicated | `/workspace/<projectId>` | no | `/app/agent-workspace` |
| `output` | `users/<key>` | `/opt/output` | no | `/app/mcp-output` |
| `servers` | (none) | `/opt/mcp_servers` | yes | `/app/mcp-servers` |
| `graph_db` | (none) | `/opt/graph_db` | yes | `/app/graph_db` |
| `custom_templates` | (none) | `/opt/nuclei-templates` | yes | `/app/nuclei-templates`; left out when empty |
| `volume:templates` | `redamon-kali-nuclei-templates` | `/root/nuclei-templates` | yes | named volume |
| `volume:osv` | the orchestrator's OSV database volume | `/osv-db` | yes | named volume |

Rules:

- A project id that fails the rule above refuses the whole plan
  (`invalid_project_id`), and so does a bare string in place of a list. The
  workspace root itself and `.staging` can never appear.
- Nothing else is mounted: no Docker socket, no secret, no other person's folder.
- An empty project list is valid: a sandbox with no project folder.
- The orchestrator creates a missing project or output folder before mounting it
  (`mkdir`, then an explicit `chmod 0777` the umask cannot narrow), so Docker never
  creates an empty root-owned folder in its place.
- A bind mount follows the folder, not its path: a project folder is never replaced
  while the project exists (a workspace reset empties it, an import swaps an entry
  inside it), and it is removed on deletion only after every instance mounting it
  has stopped.
- On a host whose filesystem ignores case, two project ids that differ only in
  case would name one folder. RedAmon creates lower-case ids only, and the agent's
  own workspace shares that property.

## 6. The container

| Setting | Value |
| :------ | :---- |
| Fixed environment | `PYTHONUNBUFFERED=1`, `PYTHONPATH=/opt:/opt/mcp_servers`, `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/osv-db`, `PYTHONDONTWRITEBYTECODE=1`, `MCP_TRANSPORT=sse`, `MCP_HOST=0.0.0.0`, the server ports (`NETWORK_RECON_PORT=8000`, `NUCLEI_PORT=8002`, `METASPLOIT_PORT=8003`, `NMAP_PORT=8004`, `PLAYWRIGHT_PORT=8005`, `MSF_PROGRESS_PORT=8013`, `HYDRA_PROGRESS_PORT=8014`, `TERMINAL_WS_PORT=8016`), `MSF_AUTO_UPDATE=false`, `NUCLEI_AUTO_UPDATE=false`, `REDAMON_AGENT_URL=http://agent:8080`, `WEBAPP_API_URL=` (empty), `REDAMON_SANDBOX_MODE=per_user` |
| Per-instance environment | `MCP_AUTH_TOKEN` and `TUNNEL_AUTH_TOKEN`, two independent random 32-byte tokens; `REDAMON_SANDBOX_KEY`, the view's key; `MSF_REVERSE_PORT`, the pool port or `4444`; `TERMINAL_MAX_SESSIONS` copied from the orchestrator when it holds a number |
| Never in the environment | the webapp, agent, scanner and orchestrator keys (`INTERNAL_API_KEY`, `SCANNER_API_KEY`, `AUTH_SECRET`, `ORCHESTRATOR_API_KEY`, ...), any database or Neo4j credential, the instance's ngrok and chisel credentials, and any user id (only the key) |
| Limits | memory and memory+swap equal the envelope (1 GiB by default); 4096 processes; half the host's CPUs, at least 1 and at most 4 |
| Privileges | `NET_ADMIN`, `NET_RAW`, `seccomp=unconfined`, as the shared container has today. No `cap_drop` and no `no-new-privileges`: the tools need root's file access and `execve` unchanged |
| DNS | `8.8.8.8`, `8.8.4.4` |
| Restart policy | none: the orchestrator manages the lifecycle |
| Healthcheck | a Python probe that connects to ports 8000, 8002, 8003, 8004, 8005, 8013, 8015 and 8016 on `127.0.0.1` and fails unless all accept; every 2 s, 2 s timeout, 3 retries, a start period equal to the start timeout |
| Published ports | none, except the pool port when `KALI_SANDBOX_PORT_POOL` is set, bound on `127.0.0.1` unless the variable names another address |

Ports inside the container: 8000 network recon, 8002 nuclei, 8003 Metasploit,
8004 nmap, 8005 Playwright, 8013 Metasploit progress and session manager, 8014
Hydra progress, 8015 tunnel manager, 8016 terminal, 4040 the ngrok agent API, 4444
(or the pool port) the reverse-shell listener. Every port but 4040 and the listener
checks the instance's bearer token. The ngrok agent API on `0.0.0.0:4040`
(`mcp/servers/tunnel_manager.py`) checks nothing, so reaching a sandbox's address is
enough to drive its tunnels: that is why nothing but the agent, the capture proxy
and an operator's own lab may sit on a sandbox network.

## 7. The network

| Setting | Value |
| :------ | :---- |
| Name | `redamon-sbx-<key>`: one per person and view, shared by that view's instances |
| Driver | `bridge`, not internal (the tools need NAT egress) |
| Address | the lowest free `/28` of `10.214.0.0/16` that overlaps no subnet of any existing Docker network; the gateway is its first host address; chosen under one global lock |
| Members | the view's instances; the agent container (found by its compose service label, falling back to the name `redamon-agent`) with the alias `agent` only; the capture proxy (`redamon-capture-proxy`) when it runs |
| Guest conditions | both guests join with gateway priority `-1000`, so their default route stays on their own networks, and only when their `HostConfig.Sysctls` holds `net.ipv4.ip_forward=0`; the proxy also only when its blocked ranges include `10.214.0.0/16` |
| Guests kept attached | every `ensure` that returns a running instance, every idle tick and the adoption at start check both guests on each live network and attach the missing one |
| Removal | when the view's last instance is removed: every endpoint still attached is disconnected, then the network is removed; a removal that fails is retried at the next idle tick |

The agent never addresses another service through a sandbox network: every
address it dials outside the sandbox resolves on `redamon-network` or the networks
it had before.

## 8. Memory admission

A sandbox is admitted by the same memory governor as scans, as its own class:

- **Envelope**: `kali_sandbox_envelope_bytes`, 1 GiB by default, a top-level value
  of the resource profile (`recon_orchestrator/resource_profile.default.json`, with
  the fallback in `recon_orchestrator/resource_governor.py` and
  `graph_db/resource_governor.py`); an operator raises it through the host profile.
- **Admission**: one reservation per instance under the key above, with the pool
  budget and the live-memory check scans use. The "never refuse the first one"
  exemption applies per class: the first sandbox when no other sandbox is
  committed, the first scan when no other scan is. `KALI_SANDBOX_MAX_CONCURRENT`
  caps committed sandboxes; the scan count limits ignore them.
- **Refusal**: HTTP 409 with the governor's payload (`admitted`, `limitType`
  `ram` or `hard`, `resource: "kali_sandbox"`, `current`, `ceiling`,
  `settingName`, `detail`) and `code` `sandbox_ram` or `sandbox_hard`.
- **Release** at stop. An orchestrator restart re-accounts every adopted instance.
- **`/system/stats`** adds `active_sandboxes`, `sandbox_committed` and
  `sandbox_envelope` (bytes); `active_scans` counts scans only.

## 9. The lifecycle

States of an instance: `starting`, `running`, `draining` (replaced, finishing its
leases), `stopping`. Each view has at most one current instance. One lock per person
guards every decision for both views.

**ensure** (person, projects, view, needed project, wait, touch):

1. Validate the ids and the view. In `shared` mode answer `{"mode": "shared"}`.
2. Under the person's lock, stop at once every instance of the view whose projects
   are not a subset of the new list (reason `access_lost`).
3. If the current instance lacks the needed project, mark it `draining` (a rolling
   replacement) and go on as if there were none.
4. A `running` current instance: re-attach a missing guest, mark it used, return it.
5. A `starting` one: wait for the same start (bounded by the start timeout).
6. None: reserve memory (a refusal is 409), create the network if needed, create
   the folders, create and start the container, attach the agent and the capture
   proxy, then wait until the healthcheck reports healthy. An agent that does not
   meet the guest conditions fails the start (503 `sandbox_start_failed`); a proxy
   that does not is left off and logged. A start that never becomes healthy is
   stopped and released (504 `sandbox_start_timeout`).
7. `touch`: the same without waiting (the 202 answer, with `fresh` when this call
   created the instance); any error or refusal is swallowed.

**Stop**: mark `stopping` (new leases refused), stop with a 10 s grace, remove the
container (wiping its writable layer), remove the network when the view has no
instance left, release the reservation, drop the leases.

**Stop a project**: for every person, stop every instance of either view that mounts
the project. Project deletion calls it before the folder is purged.

**Idle loop**, every 60 s, per instance:

- a server-code or image change first marks a `running` instance `draining` (it
  stops with reason `replaced`); a missing image changes nothing;
- `draining`: stop when no lease is left;
- `running` with a lease other than `hold`: keep;
- `running` with only a `hold`: stop after 8 hours without use (`hold_unused`),
  with a warning from the seventh hour;
- `running` with no lease: stop after the idle minutes without use (`idle`);
- then every live network gets the guest check, and a failed network removal is
  retried.

The loop runs in both modes, so per-user instances left after a switch back to
`shared` stop as they go idle.

**Adoption** at orchestrator start: every running, healthy container labelled
`redamon.sandbox=1` with contract `1` is adopted (view from its label, projects from
its `/workspace/<id>` mounts, tokens from its environment), its memory re-accounted
and its guests checked. The templates refresher is left to finish. Every other
labelled container is removed, and every labelled network with no container.

**Reconcile** (person, own projects, act-as projects): stop every instance whose
projects are no longer a subset of its view's list; start nothing.

**Stop reasons**: `idle`, `hold_unused`, `access_lost`, `account_disabled`,
`account_deleted`, `project_deleted`, `last_project_deleted`, `emergency`,
`operator`, `replaced`, `start_failed`. A stop for `account_deleted` also deletes the
person's output folders of both views, whether or not an instance is running; no
other stop touches them.

**Record**: the orchestrator logs one structured line per start and stop (key, view,
instance, projects hash, reason; never a token). The webapp writes an audit row for
each start it caused (`sandbox.started`) and each stop it asked for
(`sandbox.stopped`, with the reason and the count), through `writeAudit`
(`webapp/src/lib/audit.ts`), with labels in `webapp/src/lib/authz/auditLabels.ts`.

## 10. Leases

| Kind | Taken by | Counts as use |
| :--- | :------- | :------------ |
| `run` | a chat run and its Fireteam members | yes |
| `terminal` | an open terminal socket | yes |
| `exec` | an MCP `kali_exec` command until it ends | yes |
| `job` | an agent background job until it ends | yes |
| `triage` | a triage `cve_intel` refresh | yes |
| `tradecraft` | a Tradecraft browser fetch | yes |
| `interact` | a Sessions-page interaction, or a tunnel push | yes |
| `hold` | the agent's watcher while the instance holds live sessions or jobs, or an active tunnel | no |

Taking and renewing a lease is one idempotent call keyed by a lease id the agent
chooses: it extends the lease to 90 s from now. A `draining` instance accepts
renewals of existing leases only (409 `sandbox_draining` otherwise); a `stopping`
or absent one refuses (409 `sandbox_not_running`), and the agent then asks for the
sandbox again. An orchestrator restart loses leases; the next renewals recreate
them.

## 11. The orchestrator API

Every route requires the orchestrator key, as every other orchestrator route does.
Bodies are JSON.

| Route | Body | Answers |
| :---- | :--- | :------ |
| `POST /sandboxes/ensure` | `{user_id, view, projects, need_project, wait, touch}` | 200 `{mode, user_id, view, instance, host, token, tunnel_token, ports, reverse_port, projects, state: "running", fresh, stop_at, stop_reason, warn}`; 202 `{mode, state: "starting", instance, fresh}` when not waiting; 200 `{mode: "shared"}` in shared mode; 409 a refusal (section 8); 400 `invalid_project_id`, `invalid_user_id` or `invalid_view`; 503 `sandbox_image_missing` or `sandbox_start_failed`; 504 `sandbox_start_timeout` |
| `POST /sandboxes/{user_id}/leases` | `{instance, lease_id, kind}` | 200 `{expires_at, state, stop_at, warn}`; 404 `unknown_instance`; 409 `sandbox_not_running` or `sandbox_draining` |
| `DELETE /sandboxes/{user_id}/leases/{lease_id}` | none | 204 |
| `POST /sandboxes/{user_id}/reconcile` | `{projects, act_as_projects}` | 200 `{stopped}` |
| `POST /sandboxes/{user_id}/stop` | `{reason}` | 200 `{stopped}` (both views) |
| `POST /sandboxes/stop-project` | `{project_id, reason}` | 200 `{stopped}`; 400 `invalid_project_id` |
| `POST /sandboxes/stop-all` | `{reason}` | 200 `{stopped}` |
| `GET /sandboxes/{user_id}` | none | 200 `{mode, instances: [{instance, view, state, projects_hash, created_at, last_used, lease_kinds, stop_at, stop_reason, warn, reverse_port}]}`, never a token |
| `GET /sandboxes` | none | 200 `{mode, sandboxes: [{user_id, view, instance, host, token, state}]}` |
| `GET /sandboxes/mode` | none | 200 `{mode}` (removed with the switch) |

`ports` names `network_recon` 8000, `nuclei` 8002, `metasploit` 8003, `nmap` 8004,
`playwright` 8005, `sessions` 8013, `hydra` 8014, `tunnel` 8015, `terminal` 8016
and `ngrok_api` 4040. `host` is the container name, which resolves only on the
person's sandbox network. `fresh`, in both the 200 and the 202 answer, is true when
the call created the instance: a call that joins a start another call began gets
`false`, so the start's audit row and tunnel reset happen exactly once. Times are
epoch seconds.

## 12. The webapp gateway

The webapp decides who may have a sandbox and with which projects; the
orchestrator only enforces the list it is given.

- **Projects of a sandbox**: the person's own projects, plus the projects shared
  with them whose effective toggles (owner consent applied) include "Use AI agent"
  or "Exploitation & shells". With sharing off: own projects only. In the `act_as`
  view: only the projects whose acting access holds one of those toggles, which
  are the person's own projects. Built only from the helpers in
  `webapp/src/lib/authz/` (`visibleProjects.ts`, `projectAccess.ts`).
- **Who may have one**: an account that exists, is not disabled and holds (read
  fresh) at least one of `agent:chat`, `agent:kali_exec` or
  `platform:kali_terminal`; anyone else gets 403 `sandbox_user_refused`. A needed
  project outside the list is 403 `sandbox_project_refused`.
- **ensure** waits on the orchestrator for at most the start timeout plus 15 s (the
  30 s default of `orchestratorFetch` in `webapp/src/lib/orchestrator.ts` would cut
  a slow cold start). When the answer, waiting (200) or not (202), is `fresh`, it
  writes the `sandbox.started` audit row and, for the `own` view, turns the
  person's tunnels off (section 17).
- **touch** starts a sandbox in the background, never awaited, every error
  swallowed and logged once; a fresh 202 gets the same audit row and tunnel reset. Minting a WebSocket ticket for the agent or the
  terminal touches the ticket's person (the `act_as` view when the ticket carries
  `act`).
- **reconcile**, **stop**, **stop-all** and **stop a project** relay to the
  orchestrator after an access loss, an account end, an emergency stop, an
  operator's stop or a project deletion, then tell the agent to forget its clients
  of that person, and write the `sandbox.stopped` row.

Internal routes, for the agent only (master key, listed in the internal-route
allowlist of `webapp/src/middleware.ts`):

| Route | Body | Does |
| :---- | :--- | :--- |
| `POST /api/internal/agent/sandbox/ensure` | `{userId, projectId?, wait?, actingAs?}` | ensure, with the checks above |
| `POST /api/internal/agent/sandbox/lease` | `{userId, instance, leaseId, kind}` | take or renew a lease |
| `POST /api/internal/agent/sandbox/release` | `{userId, leaseId}` | release a lease |
| `GET /api/internal/agent/sandbox/list` | none | the running sandboxes |

The user id in these bodies is asserted by the agent, which takes it from a verified
ticket, token or job; the routes re-check the account but cannot prove whom the
agent acts for. They widen nothing: the master key already reaches the agent's
`/kali/exec`, and scan containers carry `SCANNER_API_KEY`, which these routes refuse
(`webapp/src/lib/session.ts`). They never log a body or a token.

The browser reads its own sandbox state through `GET /api/agent/sandbox/status`
(permission `agent:sessions`): the signed-in person's own instances (`state`,
`stop_at`, `stop_reason`, `warn`), never another person's.

## 13. The agent

The agent routes every Kali call by **person**, never by tenant: the person is the
run's actor (`agentic/decision_check.py`), or the owner of the MCP token, the
terminal ticket, the triage run or the Tradecraft job that started the work. The
`act_as` view is used when the work is an admin acting as the person.

- A chat run acquires its sandbox lazily: the first Kali tool call inside the run
  takes a `run` lease, so a run that uses no Kali tool starts no sandbox.
- Each person has their own client for the five MCP servers, with their own
  instance's bearer token.
- In `per_user` mode, work with no person fails (`no_user`); a call is never sent
  to another person's sandbox, to the other view of the same person, or to the
  shared container.

Agent routes that change in `per_user` mode:

| Route | Change |
| :---- | :----- |
| `POST /kali/exec` | the body gains `user_id` (the MCP token's owner), required; when the sandbox is not running, the job is created at once with `status: "starting"` |
| `GET /kali/exec/{job_id}`, `POST .../cancel` | show `starting` while the job waits for the sandbox, and an `error_code` on a sandbox failure |
| `GET /sessions` | asks every running sandbox at once (5 s each); every entry carries `sandbox: <instance>`, and `unavailable` names the sandboxes that did not answer |
| `POST /sessions/{id}/interact`, `/sessions/{id}/kill`, `/jobs/{id}/kill`, `/session-chat-map`, `/non-msf-sessions` | take `?sandbox=<instance>` (required; an unknown instance is 404). `shared` reaches the shared container while it still runs |
| `GET /tunnel-status` | requires the master key and `?user_id=`; answers that person's own tunnels |
| `WS /ws/kali-terminal` | routes to the ticket's person and sends `sandbox_status` frames before the shell starts, or instead of it |
| `POST /sandboxes/{user_id}/drop` | new: forget every client of the person |
| `POST /sandboxes/{user_id}/tunnel` | new: push the person's tunnel configuration to their sandbox |
| `POST /emergency-stop-all` | also stops the runs in every running sandbox |

## 14. Events and messages

| Where | Shape |
| :---- | :---- |
| Agent WebSocket | event `sandbox_status`, payload `{state: "starting" \| "ready" \| "unavailable", reason?: "ram" \| "hard" \| "error" \| "refused" \| "stopped", detail?, limit?}` (the limit is the governor payload). Sent, never stored |
| Tool result to the model | `sandbox unavailable: not enough memory`; `sandbox unavailable: the instance's sandbox limit is reached`; `sandbox unavailable: the sandbox could not start`; `sandbox unavailable: this person may not use the Kali sandbox on this project`; `sandbox stopped during the call` |
| Terminal socket | a frame `{"type": "sandbox_status", "state": "starting"}`; on a memory or limit refusal a frame with `state: "unavailable"`, the reason and the limit, then close code 1013; on `refused` the same frame, then close code 1008 |
| MCP `kali_exec`, `kali_output` | status `starting`; `error_code` one of `ram`, `hard`, `sandbox_error`, `sandbox_refused`, `sandbox_stopped` |
| Share dialog, "Use AI agent" and "Exploitation & shells" | "This person's agent runs on this project use your WPScan, URLScan and ProjectDiscovery keys inside a Kali sandbox, where this person can read them while their runs use them." |
| Modal in the terminal and the chat drawer | "Not enough memory" (or "Sandbox limit reached") with the figures in GB, buttons Retry and Close; "Kali sandbox not available" for a refusal, button Close only. A refused warm-up shows nothing |
| Sessions panel and the admin Operations view | "N sandboxes did not answer; their sessions are not shown" above the list when some did not answer, never an error page |

## 15. Environment variables

Every variable is optional, absent from `.env` by default, read by the
orchestrator only (through its compose `environment:` block), with its default in
code.

| Variable | Default | Effect |
| :------- | :------ | :----- |
| `KALI_SANDBOX_IDLE_MINUTES` | 20 | minutes without use before an idle sandbox stops; an integer of at least 1, anything else is 20 |
| `KALI_SANDBOX_MAX_CONCURRENT` | unset: no count limit | the most running sandboxes; `0` blocks every new sandbox; anything but an integer of at least 0 is no limit |
| `KALI_SANDBOX_PORT_POOL` | unset: no pool | `[bind-ip:]first-last`: each sandbox gets one host port from the range for direct reverse shells, bound on `127.0.0.1` unless an address is given; a malformed value is no pool, and is logged |
| `KALI_SANDBOX_MODE` | `shared` | the temporary switch (section 3) |

Not variables: the image, the lease timings, the 8-hour and 1-hour figures, the
template refresh period, the subnet range and the per-sandbox limits. The envelope
is a resource-profile value. `KALI_MEM`, `KALI_PIDS` and `KALI_CPUS` size only the
shared container.

## 16. Timings

| Name | Seconds |
| :--- | ------: |
| Lease lifetime | 90 |
| Lease renewal | 30 |
| Idle stop (default) | 1 200 |
| Idle check | 60 |
| Hold without use, maximum | 28 800 |
| Warning before that | 3 600 |
| Agent hold watcher | 60 |
| Stop grace | 10 |
| Start timeout | 300 |
| Templates refresh | 86 400 |
| Agent's wait on the webapp for `ensure` | 330 (start timeout + 30) |
| Agent's wait on the webapp, other calls | 10 |
| Webapp's wait on the orchestrator for a waiting `ensure` | 315 (start timeout + 15) |
| Each sandbox asked by a fan-out (`/sessions`, the hold watcher, stopping all runs) | 5 |

Each layer waits longer than the one below it, so the orchestrator answers a slow
start before the webapp gives up, and the webapp before the agent does. A cold start
takes a few seconds; the first Metasploit call in a fresh sandbox waits another
15-18 s while `msfconsole` loads.

## 17. Tunnels and reverse shells

- Each sandbox runs its own tunnel manager on 8015 with its own token.
- A person's tunnel comes from their own settings (`tunnelsEnabled`,
  `ngrokAuthtoken`, `chiselServerUrl`, `chiselAuth`), pushed by the webapp through
  the agent to their sandbox. An empty configuration stops the tunnel.
- A freshly started sandbox has no tunnel, and the webapp turns the person's
  `tunnelsEnabled` off at that start, so a tunnel never comes back silently.
- The reverse-shell listener inside the container is `MSF_REVERSE_PORT` (the pool
  port, or 4444). It is reachable from outside only through the person's tunnel, or
  through the pool port when one is set.
- The agent's LHOST/LPORT hints read the person's tunnel or, with a pool port, the
  host's LAN address and that port.

## 18. Keeping the tools current

- Nuclei templates live in the named volume `redamon-kali-nuclei-templates`,
  filled and refreshed daily by a short-lived refresher container
  (`redamon-kali-templates-refresh`), and mounted read-only in every sandbox. nuclei
  runs normally against read-only templates and never updates them during a scan.
- Metasploit modules ship with the image; `./redamon.sh update` rebuilds its last
  layers with the day's module update.
- Packages a shell installs at run time are lost at the next stop.

## 19. Roll-back

- While the default is `shared`, nothing a user sees changes; any part can be
  reverted on its own.
- After the default flips, set `KALI_SANDBOX_MODE=shared` for the orchestrator to
  go back to the shared container; per-user instances still running stop as they
  go idle.
- After the shared container is removed, roll back by reverting that removal and
  the switch removal, then `./redamon.sh update`.

Every roll-back to the shared container gives up the separation this page
describes: one container, one set of tokens and one network for everybody again.

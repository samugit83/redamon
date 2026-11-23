# Kali Sandboxes: One per Person, Started on Demand

RedAmon runs its offensive tools (network recon, nuclei, Metasploit, nmap,
Playwright, Hydra, the terminal, tunnels) inside containers built from the Kali
image. Each person who reaches the Kali tools gets their own container, started by
the recon orchestrator on first need and stopped when unused.

A **sandbox** is one of those containers. It mounts only the project folders its
person may run the agent on, has its own random tokens, its own Metasploit
console and session manager, its own limits, and its own network, to which only
the agent and the capture proxy are attached. Removing the container at every stop
wipes everything a shell wrote outside the project folders and the person's output
folder.

> **Status.** Per-user sandboxes are the only mode. There is no shared Kali
> container: an update from an older release removes the old `redamon-kali`
> container once the new images are built (section 3), and every session still
> open in it ends then.

## Table of Contents

1. [The contract](#1-the-contract)
2. [How it works](#2-how-it-works)
3. [Installing, updating and operating](#3-installing-updating-and-operating)
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
19. [Known limits](#19-known-limits)
20. [Tests](#20-tests)
21. [Roll-back](#21-roll-back)

---

## 1. The contract

The code is the contract; this page explains it. Its names, values and pure rules
live in two Python copies, and the TypeScript copy carries what the webapp uses:

| File | Read by |
| :--- | :------ |
| `recon_orchestrator/sandbox_contract.py` | the orchestrator, which starts, stops and adopts sandboxes |
| `agentic/sandbox_contract.py` | the agent, which routes each Kali call to its person's sandbox |
| `webapp/src/lib/sandbox/contract.ts` | the webapp, which decides who may have a sandbox and with which projects |

The two Python files are byte-identical. `tests/test_sandbox_contract.py` fails when
they differ by one byte, when a TypeScript constant is missing or differs from the
Python value, and when a pure rule (the mount plan, the keys, the environment, the
subnet pick, the variable parsers) stops keeping persons apart. Some shapes exist
only in TypeScript and nothing compares them with Python: `SandboxPorts`, the keys
of an ensure answer's `ports`, must name every key of `PORTS`. Change the copies
together, and this page with them.

The Python contract uses the standard library only and imports nothing else from
RedAmon, so both services and the tests load it by path.

The code that applies it:

| Part | Files |
| :--- | :---- |
| Orchestrator | `recon_orchestrator/sandbox_manager.py` (start, stop, leases, idle loop, adoption), `recon_orchestrator/sandbox_templates.py` (the nuclei templates volume), the `/sandboxes` routes in `recon_orchestrator/api.py` |
| Webapp | `webapp/src/lib/sandbox/gateway.ts` (who, which folders, the calls), `orchestratorClient.ts` (the orchestrator protocol), `agentCalls.ts` (the agent's drop and tunnel routes), `lifecycle.ts` (access loss, account end, project deletion, emergency stop, the backstop), the four routes under `webapp/src/app/api/internal/agent/sandbox/`, `webapp/src/app/api/agent/sandbox/status/route.ts`, `webapp/src/app/api/admin/operations/sandboxes/stop/route.ts` |
| Agent | `agentic/sandbox_router.py` (routing by person), `agentic/sandbox_hold.py` (the hold watcher), `agentic/sandbox_http.py` (bounded reads of a sandbox's answers), `agentic/sandbox_runs.py` (stopping a run's processes), the executor in `agentic/tools.py`, the routes in `agentic/api.py` |
| Image | `mcp/kali-sandbox/Dockerfile`, `mcp/kali-sandbox/entrypoint.sh`, the servers in `mcp/servers/` |

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
  Metasploit sessions or jobs, an active tunnel) is held and it has been unused for 8
  hours (with a warning from the seventh).
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

Words used below: a **person** is who does the work (a WebSocket ticket's `sub`, an
MCP token's owner, who started a triage run or a Tradecraft job); the **tenant** is
the project's owner, whose graph, traffic and keys a request touches. Sandboxes are
routed by person; everything else keeps routing by tenant. An **instance** is one
sandbox container: a person normally has one per view, two during a rolling
replacement.

## 3. Installing, updating and operating

- **The image** is `redamon-kali-sandbox:latest`. `./redamon.sh install` builds it
  with the other tool images, `./redamon.sh up` builds it when it is missing, and it
  builds by hand with `docker compose --profile tools build kali-sandbox`. The
  compose file keeps a build-only `kali-sandbox` service under the `tools` profile:
  nothing runs from it. A checkout whose compose project is not named `redamon`
  built it as `<project>-kali-sandbox:latest`; `install`, `update` and `up` tag that
  image with the fixed name once. A start without the image answers 503
  `sandbox_image_missing`, naming those commands.
- **Updating.** `./redamon.sh update` rebuilds the image when `mcp/kali-sandbox/`
  or `mcp/requirements.txt` changed, and a completed update (not `--preview`)
  refreshes its Metasploit layers, normally once a day (section 18). A change elsewhere under `mcp/` (the servers, which every sandbox
  mounts read-only) rebuilds and restarts nothing: each running sandbox notices the
  new server code or the new image at its next idle tick and drains onto a new
  instance, without cutting what it still runs (section 9).
- **Update the agent, the webapp and the orchestrator together.** They speak one
  sandbox protocol, and `./redamon.sh update` rebuilds the agent and webapp images
  and recreates the orchestrator in the same run. A part left on an older release
  fails closed, never back to a shared container: the webapp refuses every start
  (503), or the agent answers every Kali call that the sandbox could not start.
  After a plain `git pull`, rebuild the agent and webapp images too (`docker compose
  build agent webapp`, then `./redamon.sh up`): an update with nothing left to pull
  recreates the services on the images they have.
- **The old shared container.** An installation from before per-user sandboxes ran
  one `redamon-kali` container. `./redamon.sh` removes it only when it carries this
  checkout's compose project label, so another stack's is left alone: `install`,
  `up` and `up dev` before they start the stack, `down` before it stops it, and
  `update` only after its builds and the answer to its preview, also when there was
  nothing to pull; never with `--preview`, never after a "no" or a stop at the
  update's disk or memory check. Every Metasploit session still open in it ends
  then: close them first.
- **The pentest network.** The same commands create `<project>_pentest-net`, the
  network the capture proxy and the guinea-pig labs use, when it is missing, with
  the subnet and labels compose gives it (the shared container was the only service
  compose started on it). `purge` removes it.
- **`.env`.** No sandbox variable is required (section 15). `KALI_MEM`, `KALI_PIDS`
  and `KALI_CPUS` in an existing `.env` are ignored: the memory block
  `./redamon.sh` writes no longer holds a Kali share, and the former share goes to
  the pool scans and sandboxes are admitted from (section 8). `install`, `update`
  and `up` name a `KALI_SANDBOX_MODE`, `KALI_PIDS`, `KALI_CPUS` or pinned `KALI_MEM`
  left in `.env` as ignored, once per run, and change nothing in the file.
  `MCP_AUTH_TOKEN` and `TUNNEL_AUTH_TOKEN` are still generated, because the
  single-host deploy's secrets check expects them, but no service reads them (the
  agent's environment blanks both): each sandbox gets its own pair.
- **`./redamon.sh status`** lists this stack's sandboxes under "Kali sandboxes";
  the nuclei templates refresher may appear there while it runs, once a day.
  **`down`**, **`clean`** and **`purge`** remove them; **`purge`** also removes
  their networks and the templates volume. Each selects by the label
  `redamon.sandbox=1` and this stack's owner label, never by name.
- **Logs.** `docker ps --filter label=redamon.sandbox=1` lists the sandboxes, and
  `docker logs <container>` reads one. The orchestrator logs one line per start and
  stop (section 9).
- **Restarts.** An orchestrator restart adopts the running sandboxes (section 9);
  until that adoption succeeds the sandbox routes answer 503, and it is retried
  every 30 s. Recreating the agent (`./redamon.sh update`, `docker compose up -d
  agent`) detaches it from the sandbox networks; the orchestrator attaches it again
  at the next `ensure` or idle tick, so running sandboxes keep working.
- **Several stacks on one daemon** (a test stack, a second checkout) keep apart:
  every sandbox container and network carries the owner label
  `redamon.sandbox.owner` (the orchestrator's compose project, or `standalone` when
  it cannot read it), and adoption, removal, network reuse and `./redamon.sh`
  touch only their own. The templates volume has a fixed name and is shared.
- **The orchestrator's mounts.** A sandbox binds parts of four host folders, which
  the orchestrator finds through its own compose mounts:
  `./agentic/agent-workspace:/app/agent-workspace`, `./mcp/output:/app/mcp-output`,
  `./mcp/servers:/app/mcp-servers:ro` and `./graph_db:/app/graph_db:ro`. An
  orchestrator created without one of them refuses every start (503
  `sandbox_start_failed`) and logs the missing line once; `./redamon.sh up`
  recreates it.

## 4. Names, labels and keys

| Name | Value |
| :--- | :---- |
| Image | `redamon-kali-sandbox:latest` |
| Views | `own` (the person's own work), `act_as` (an admin acting as the person) |
| Key of a view | first 16 hex characters of the SHA-256 of the user id (`own`) or of `act_as:` + the user id (`act_as`). A user id cannot contain `:`, so the two views of different persons never share a key |
| Network | `redamon-sbx-<key>` |
| Instance | 6 random hex characters, new for every start and unique among every live instance of every person, because the webapp pairs sessions and audit rows by `<instance>:<n>` |
| Container | `redamon-kali-<key>-<instance>`, also its hostname (section 6) |
| Governor reservation | `kali_sandbox:<user id>:<instance>` |
| Valid user id | `^[A-Za-z0-9_-]{1,64}$`, and not `ensure`, `stop-all` or `stop-project` (the single-segment routes under `/sandboxes/`) |
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
| `redamon.sandbox.owner` | the stack that started it (section 3) |
| `com.docker.compose.project`, `com.docker.compose.service` | empty: `docker compose build` stamps them on the image, and blanking them keeps compose from counting a sandbox as a replica of its own `kali-sandbox` service |

The nuclei templates containers (the refresher and the short populate and probe
containers, section 18) carry `redamon.sandbox=1`, `redamon.sandbox.role=templates`
and the owner label, and no user label. Sandbox networks carry the first four labels
and the owner label.

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
- The orchestrator creates a missing project or output folder before mounting it,
  so Docker never creates an empty root-owned folder in its place: the folder
  itself `0777` (the agent and the sandbox both write it), `users/` above the
  output folders `0755` (only the orchestrator adds to it), both set through the
  open descriptor so the umask cannot narrow them.
- No mount source is ever a link. Every bind source is opened one component at a
  time without following a link; a link or a non-folder anywhere on the path refuses
  the start (503 `sandbox_start_failed`). Docker resolves a source when it starts
  the container, so the orchestrator then reads every bind target from inside the
  started container (device and inode) and removes a sandbox whose mount is not
  the folder it checked, before any token leaves the orchestrator.
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
| Hostname | the container's own name. Inside, `kali-sandbox` resolves to `127.0.0.1` (`ExtraHosts` `kali-sandbox:127.0.0.1`), so the tools and prompts that name the sandbox reach it; the agent and the capture proxy, which join every sandbox network, resolve `kali-sandbox` to no sandbox, except one started before this release, which keeps that shared hostname until it drains (section 9) |
| Init | Docker's init as PID 1: it reaps the processes a shell leaves behind, which the image's own PID 1 does not, so orphans never pile up against the process limit |
| Fixed environment | `PYTHONUNBUFFERED=1`, `PYTHONPATH=/opt:/opt/mcp_servers`, `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/osv-db`, `PYTHONDONTWRITEBYTECODE=1`, `MCP_TRANSPORT=sse`, `MCP_HOST=0.0.0.0`, the server ports (`NETWORK_RECON_PORT=8000`, `NUCLEI_PORT=8002`, `METASPLOIT_PORT=8003`, `NMAP_PORT=8004`, `PLAYWRIGHT_PORT=8005`, `MSF_PROGRESS_PORT=8013`, `HYDRA_PROGRESS_PORT=8014`, `TERMINAL_WS_PORT=8016`), `MSF_AUTO_UPDATE=false`, `NUCLEI_AUTO_UPDATE=false`, `REDAMON_AGENT_URL=http://agent:8080`, `WEBAPP_API_URL=` (empty), `REDAMON_SANDBOX_MODE=per_user` |
| Per-instance environment | `MCP_AUTH_TOKEN` and `TUNNEL_AUTH_TOKEN`, two independent random 32-byte tokens; `REDAMON_SANDBOX_KEY`, the view's key; `MSF_REVERSE_PORT`, the pool port or `4444`; `TERMINAL_MAX_SESSIONS` copied from the orchestrator when it holds a number |
| Never in the environment | the webapp, agent, scanner and orchestrator keys (`INTERNAL_API_KEY`, `SCANNER_API_KEY`, `AUTH_SECRET`, `ORCHESTRATOR_API_KEY`, ...), any database or Neo4j credential, the instance's ngrok and chisel credentials, and any user id (only the key) |
| Limits | memory and memory+swap equal the envelope (1 GiB by default); 4096 processes; half the host's CPUs, at least 1 and at most 4, at CPU weight 256, below the 1024 of every service, so under contention the platform's services win over any number of sandboxes |
| Privileges | `NET_ADMIN`, `NET_RAW`, `seccomp=unconfined`. No `cap_drop` and no `no-new-privileges`: the tools need root's file access and `execve` unchanged (the `orchestrator-container-spawn` skill says why) |
| DNS | `8.8.8.8`, `8.8.4.4` |
| Restart policy | none: the orchestrator manages the lifecycle |
| Healthcheck | a Python probe that connects to ports 8000, 8002, 8003, 8004, 8005, 8013, 8015 and 8016 on `127.0.0.1` and fails unless all accept; every 2 s, 2 s timeout, 3 retries, a start period equal to the start timeout. The orchestrator reads the health once a second while a start waits |
| Published ports | none, except the pool port when `KALI_SANDBOX_PORT_POOL` is set, bound on `127.0.0.1` unless the variable names another address |

The entrypoint asks the webapp for nothing at boot: a sandbox's tunnels come only
from the agent's push (section 17). `REDAMON_SANDBOX_MODE=per_user` stays in the
fixed environment because two servers read it: `mcp/servers/tunnel_manager.py`
(the ngrok API on the loopback, the instance's MCP token accepted to read or stop
tunnels) and `mcp/servers/metasploit_server.py` (an empty session list answered
without starting `msfconsole`).

Ports inside the container: 8000 network recon, 8002 nuclei, 8003 Metasploit,
8004 nmap, 8005 Playwright, 8013 Metasploit progress and session manager, 8014
Hydra progress, 8015 tunnel manager, 8016 terminal, 4040 the ngrok agent API, 4444
(or the pool port) the reverse-shell listener. Every port but 4040 and the listener
checks the instance's bearer token. The ngrok agent API checks nothing, so it
listens on the container's loopback only
(`mcp/servers/tunnel_manager.py`); the agent reads tunnel state through the tunnel
manager on 8015. The listener checks nothing either: that is why nothing but the
agent, the capture proxy and an operator's own lab may sit on a sandbox network.

## 7. The network

| Setting | Value |
| :------ | :---- |
| Name | `redamon-sbx-<key>`: one per person and view, shared by that view's instances |
| Driver | `bridge`, not internal (the tools need NAT egress) |
| Address | the lowest free `/28` of `10.214.0.0/16` that overlaps no subnet of any existing Docker network; the gateway is its first host address; chosen under one global lock |
| Options | pinned on every network, so a daemon's `default-network-opts` cannot change them: IPv6 off, inter-container traffic on, IP masquerade on, NAT gateway mode, and a published port that names no address binding `127.0.0.1`. A network the engine made with IPv6 anyway is removed and the start refused |
| Members | the view's instances; the agent (below) with the alias `agent` only; the capture proxy (`redamon-capture-proxy`) when it runs |
| Which agent | every running replica that compose created for this stack's `agent` service (it carries compose's config-hash and container-number labels, is not a one-off `docker compose run`, and was not created through the Docker broker); failing that, the container named `redamon-agent` when it is such a replica or carries no compose label at all. A copy of the agent image started any other way is never attached, whatever its name |
| Guest conditions | both guests join with gateway priority `-1000`, so their default route stays on their own networks, and only when their `HostConfig.Sysctls` holds `net.ipv4.ip_forward=0`; the proxy also only when its `CAPTURE_BLOCKED_IPS` covers `10.214.0.0/16` and it runs as the orchestrator starts it: the current id of its image (`CAPTURE_PROXY_IMAGE`, `redamon-capture-proxy:latest` by default), `mitmdump` with no other entrypoint, and exactly one `--set rawtcp=false` (a raw TCP stream would pass its egress guard, which reads HTTP only). A start fails (503 `sandbox_start_failed`) when no agent replica meets them; a proxy that does not is left off, with one warning. A guest found at another priority is attached again |
| Guests kept attached | every `ensure` that returns a running instance, every idle tick, the adoption at start, and a capture proxy the orchestrator has just (re)started check both guests on each live network and attach the missing one |
| Reuse | a network of that name the orchestrator did not make (other labels, another owner, the broker's label, another driver, a subnet outside the pool) is never used: the start fails |
| Removal | when the view's last instance is removed: every endpoint still attached (the guests, a lab an operator connected) is disconnected, then the network is removed; a removal that fails is retried at the next idle tick, under the allocation lock, and its `/28` stays taken until then |

The agent never addresses another service through a sandbox network: every
address it dials outside the sandbox resolves on `redamon-network` or the networks
it had before. Docker also resolves the agent's container name and short id on a
sandbox network (it always does on a user-defined network); that adds no address
the alias does not already give.

The agent refuses any user MCP server or custom model endpoint that would reach
`10.214.0.0/16`, checked when the connection is opened and following no redirect,
so one person's settings never point the agent at another person's sandbox.

## 8. Memory admission

A sandbox is admitted by the same memory governor as scans, as its own class:

- **Envelope**: `kali_sandbox_envelope_bytes`, 1 GiB by default, a top-level value
  of the resource profile (`recon_orchestrator/resource_profile.default.json`, with
  the fallback in `recon_orchestrator/resource_governor.py` and
  `graph_db/resource_governor.py`); an operator raises it through the host profile.
- **The pool**: scans and sandboxes are admitted from one pool. The share
  `./redamon.sh` once set aside for the shared Kali container is part of that pool
  (`docs/readmes/README.MEMORY_GOVERNOR.md`); a host whose pool cannot hold one
  sandbox envelope fails the installer's memory check.
- **Admission**: one reservation per instance under the key above, with the pool
  budget and the live-memory check scans use. The "never refuse the first one"
  exemption applies per class: the first sandbox when no other sandbox is
  committed, the first scan when no other scan is. `KALI_SANDBOX_MAX_CONCURRENT`
  caps committed sandboxes, also with the governor off; the scan count limits and
  the per-person scan quota ignore sandboxes. A person holds at most two
  reservations per view (the current instance and one draining).
- **Refusal**: HTTP 409 with the governor's payload (`admitted`, `limitType`
  `ram` or `hard`, `resource: "kali_sandbox"`, `current`, `ceiling`,
  `settingName`, `detail`) and `code` `sandbox_ram` or `sandbox_hard`. Critically
  low host memory is a `ram` refusal too.
- **Release** at stop. The 30 s reaper never frees a live instance's reservation
  (the manager lists every key it holds); an orchestrator restart re-accounts every
  adopted instance at its container's memory limit.
- **`/system/stats`** adds `active_sandboxes`, `sandbox_committed` and
  `sandbox_envelope` (bytes) to `mem`; `active_scans` counts scans only. Its
  `remaining_for_new` is what a new scan could be admitted with: while no scan is
  committed, the sandboxes' reservations never hold back a queued scan that
  admission would let in (only live memory does).

## 9. The lifecycle

States of an instance: `starting`, `running`, `draining` (replaced, finishing its
leases), `stopping`. Each view has at most one current instance and at most one
draining one. One lock per person guards every decision for both views, a lease
and an idle stop included; one global lock guards subnet and port allocation.
Docker calls run in threads, and the work done under a person's lock runs as its
own task, so a caller that hangs up mid-start never leaves half a sandbox behind.
Every timer reads a steady clock (wall time at start, advanced by the monotonic
clock), so a clock change never stops or keeps a sandbox.

**ensure** (person, projects, view, needed project, wait, touch):

1. Validate the ids and the view (400 `invalid_user_id`, `invalid_project_id`,
   `invalid_view`); a needed project must be in the list.
2. Under the person's lock, stop at once every instance of the view whose projects
   are not a subset of the new list (reason `access_lost`).
3. If the current instance lacks the needed project, a replacement starts first,
   under its own reservation, and only then is the old one marked `draining` (a
   rolling replacement): a refused or failed replacement leaves the current one
   current. An older draining instance of the view stops (`replaced`).
4. A `running` current instance: re-attach a missing guest, mark it used, return it.
5. A `starting` one: wait for the same start (bounded by the start timeout plus
   30 s).
6. None: reserve memory (a refusal is 409), create the view's network if needed
   and attach the agent and the capture proxy to it (section 7), pick a pool port,
   check and create the folders, create and start the container, read its mounts
   back from inside, then wait until the healthcheck reports healthy. A start that
   never becomes healthy is stopped and released (504 `sandbox_start_timeout`); one
   that turns unhealthy or exits is 503 `sandbox_start_failed`.
7. `touch`: the same without waiting (the 202 answer, with `fresh` when this call
   created the instance); any error or refusal is swallowed.

A stop of the person, of everybody, of a project the start mounts, or a reconcile
whose list no longer covers it fences an `ensure` still waiting for the lock: it
fails with `sandbox_start_failed` ("ask again") instead of starting from the list
it read before.

**Stop**: mark `stopping` (new leases refused), stop with a 10 s grace, remove the
container (wiping its writable layer), remove the network when the view has no
instance left, release the reservation, drop the leases. A container that cannot be
removed is killed and disconnected from its network at once, keeps its reservation,
and its removal is retried at the next idle tick.

**Stop a project**: for every person, stop every instance of either view that mounts
the project. Project deletion calls it before the project row is deleted and again
after (an `ensure` that read the list before the row went may have started one),
and only then purges the folder.

**Idle loop**, every 60 s, person by person (one failing person is logged and never
stops the pass for the others), per instance:

- first, a `running` instance on an image other than the current
  `redamon-kali-sandbox:latest`, or on other server code (its `servers` label), is
  marked `draining`; a missing image changes nothing, and the next start answers
  `sandbox_image_missing`;
- `draining`: stop (`replaced`) when no lease is left;
- `running` with a lease other than `hold`: keep;
- `running` or `draining` with only a `hold`: stop after 8 hours without use
  (`hold_unused`), with a warning from the seventh hour;
- `running` with no lease: stop after the idle minutes without use (`idle`);
- a start that never settled is stopped (`start_failed`) 60 s after its timeout;
- then the draining instances of a view that has a new instance get their tunnels
  turned off (section 17), every live network gets the guest check, and a failed
  network removal is retried.

**Adoption** at orchestrator start, over this stack's containers only (the owner
label): a running, healthy container labelled `redamon.sandbox=1` with contract `1`
is adopted when it is exactly what this orchestrator would start for it: its name,
labels, image (`redamon-kali-sandbox:latest` or an older build of it), entrypoint,
user, environment (the fixed values, its key, its reverse port, two well-formed
tokens), mounts (rebuilt from the plan), hostname and extra hosts, privileges,
limits, DNS, restart policy, its single network and its published port, with every
host setting the manager never sets left empty, and no Docker broker label. One on
an older image, whose pool port no longer fits the pool, started without an init
process, or with the hostname `kali-sandbox` every sandbox once shared (and no
extra hosts) is adopted `draining`, and stops as `replaced` once unused; any other
hostname or extra-hosts entry is refused. Its view comes from its
label, its projects from its `/workspace/<id>` mounts, its tokens from its
environment; its memory is re-accounted, its guests checked, and for one lease
lifetime (90 s) it is not stopped for holding no lease, while the agent's renewals
and the hold watcher take theirs again (an orchestrator restart loses every lease).
Two instances of one view are ordered by their created label and then by Docker's
own creation time: the newer one is current. Every other labelled container of
this stack is removed, and every labelled network no adopted instance uses. The
templates containers are left to finish; a look-alike carrying the Docker broker's
label is removed.

**Reconcile** (person, own projects, act-as projects): stop every instance whose
projects are no longer a subset of its view's list; start nothing.

**Stop reasons**: `idle`, `hold_unused`, `access_lost`, `account_disabled`,
`account_deleted`, `project_deleted`, `last_project_deleted`, `emergency`,
`operator`, `replaced`, `start_failed`. A stop for `account_deleted` also deletes the
person's output folders of both views, found by key, whether or not an instance is
running (a link there is unlinked, never followed); no other stop touches them.

**Record**: the orchestrator logs one line per start, drain and stop (key, view,
instance, projects hash, reason; never a token or a user id). The webapp writes an
audit row for each start it caused (`sandbox.started`) and each stop it asked for
that stopped something (`sandbox.stopped`, with the reason and the count), through
`writeAudit` (`webapp/src/lib/audit.ts`), with labels in
`webapp/src/lib/authz/auditLabels.ts`. The actor is the person whose work caused
it (the system on the person's behalf in the `act_as` view), or the admin who
pressed the stop.

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
| `hold` | the agent's hold watcher while the instance holds live sessions, jobs or listeners, or an active tunnel | no |

Taking and renewing a lease is one idempotent call keyed by a lease id the agent
chooses (a UUID): it extends the lease to 90 s from now. Leases belong to an
instance of the person: another person's instance, or an instance id of the wrong
shape, is 404 `unknown_instance`; a lease id or kind outside the contract is 400
`invalid_sandbox_request`. A `draining` instance accepts renewals of existing
leases only (409 `sandbox_draining` otherwise); a `stopping` or absent one refuses
(409 `sandbox_not_running`), and the agent then asks for the sandbox again.
Releasing a use lease counts as use: the idle minutes count from the release. An
orchestrator restart loses leases; the next renewals recreate them.

## 11. The orchestrator API

Every route requires the orchestrator key, as every other orchestrator route does.
Bodies are JSON. An error answers FastAPI's wrapper `{"detail": {"code",
"detail"}}`, with a contract code and a fixed sentence (never a path, a token or
Docker's text); a refusal adds the governor's payload inside `detail`. Until the
adoption at start has succeeded every route answers 503 `sandbox_start_failed`
("the sandbox manager is not ready yet").

| Route | Body | Answers |
| :---- | :--- | :------ |
| `POST /sandboxes/ensure` | `{user_id, view, projects, need_project, wait, touch}` | 200 `{user_id, view, instance, host, token, tunnel_token, ports, reverse_port, projects, state: "running", fresh, stop_at, stop_reason, warn}`; 202 `{state: "starting", instance, fresh}` when not waiting (a swallowed `touch` failure is 202 `{state: "unavailable", instance: null, fresh: false}`); 409 a refusal (section 8); 400 `invalid_project_id`, `invalid_user_id` or `invalid_view`; 503 `sandbox_image_missing` or `sandbox_start_failed`; 504 `sandbox_start_timeout` |
| `POST /sandboxes/{user_id}/leases` | `{instance, lease_id, kind}` | 200 `{expires_at, state, stop_at, warn}`; 400 `invalid_user_id` or `invalid_sandbox_request`; 404 `unknown_instance`; 409 `sandbox_not_running` or `sandbox_draining` |
| `DELETE /sandboxes/{user_id}/leases/{lease_id}` | none | 204 |
| `POST /sandboxes/{user_id}/reconcile` | `{projects, act_as_projects}` | 200 `{stopped}` |
| `POST /sandboxes/{user_id}/stop` | `{reason}` | 200 `{stopped}` (both views); 400 `invalid_stop_reason` |
| `POST /sandboxes/stop-project` | `{project_id, reason}` | 200 `{stopped}`; 400 `invalid_project_id` or `invalid_stop_reason` |
| `POST /sandboxes/stop-all` | `{reason}` | 200 `{stopped}`; 400 `invalid_stop_reason` |
| `GET /sandboxes/{user_id}` | none | 200 `{instances: [{instance, view, state, projects_hash, created_at, last_used, lease_kinds, stop_at, stop_reason, warn, reverse_port}]}`, never a token |
| `GET /sandboxes` | none | 200 `{sandboxes: [{user_id, view, instance, host, token, state}]}`: the running and draining instances, for the agent's fan-out through the webapp |
| any other path under `/sandboxes/` | | 404 `unknown_instance` (the webapp reads a 404 without a code as an orchestrator that has no sandbox routes) |

`ports` names `network_recon` 8000, `nuclei` 8002, `metasploit` 8003, `nmap` 8004,
`playwright` 8005, `sessions` 8013, `hydra` 8014, `tunnel` 8015, `terminal` 8016
and `ngrok_api` 4040. `host` is the container name, which resolves only on the
person's sandbox network. `fresh`, in both the 200 and the 202 answer, is true when
the call created the instance: a call that joins a start another call began gets
`false`, so the start's audit row and tunnel reset happen exactly once.
`lease_kinds` lists unexpired leases; `stop_at` is when the idle loop stops the
instance if nothing changes (the last use plus 8 hours under a hold, else plus the
idle minutes); `stop_reason` is set only for an instance on its way out (draining or
stopping); `warn` is the hold cap's warning. Times are epoch seconds.

## 12. The webapp gateway

The webapp decides who may have a sandbox and with which projects; the
orchestrator only enforces the list it is given.

- **Projects of a sandbox**: the person's own projects, plus the projects shared
  with them whose access, read fresh (owner consent, expiry and account applied),
  reaches "Use AI agent" or "Exploitation & shells". With sharing off: own projects
  only. In the `act_as` view: only the projects whose acting access holds one of
  those, which are the person's own projects (a share reads as Read there). Built
  only from the helpers in `webapp/src/lib/authz/` (`visibleProjects.ts`,
  `projectAccess.ts`); a stored id the contract refuses is never mounted (logged
  once). Nothing is cached.
- **Who may have one**: an active account that holds (read fresh) at least one of
  `agent:chat`, `agent:kali_exec` or `platform:kali_terminal`; anyone else gets
  403 `sandbox_user_refused`. The agent's project id is a hint checked against the
  list, never a grant: one outside it is 403 `sandbox_project_refused`.
- **ensure** waits on the orchestrator for at most the start timeout plus 15 s (the
  30 s default of `orchestratorFetch` in `webapp/src/lib/orchestrator.ts` would cut
  a slow cold start); every other call keeps that default. When the answer, waiting
  (200) or not (202), is `fresh`, it turns the person's tunnels off (`own` view,
  section 17; a start whose tunnels cannot be turned off is stopped instead of
  handed out), writes the `sandbox.started` row, and reads access again: a stop can
  overtake a start, so an account refused now stops the person's sandboxes, and a
  project no longer allowed is reconciled away and the start retried once on the
  new list.
- **An orchestrator out of reach**, or answering outside the contract (an older
  release's `{mode: "shared"}` included), is 503
  `orchestrator_unavailable`. Answers are cut to the contract's keys, and an error
  keeps its code only when it is the contract's (read from `{detail: {code}}` or a
  bare `{code}`); anything else is `orchestrator_error`, never the body's text.
- **touch** starts a sandbox in the background, never awaited, every error
  swallowed and logged at most once a minute per code; a fresh 202 gets the same
  audit row and tunnel reset. Minting a WebSocket ticket for the agent or the
  terminal touches the ticket's person (the `act_as` view when the ticket carries
  `act`), at most once per person and view every 30 s.
- **Leases**: the lease route re-reads the account, so a disabled or stripped
  account's renewals stop; a release is never refused.
- **Stops** relay to the orchestrator. Every one that stopped something writes the
  `sandbox.stopped` row; a person's stop and the stop of everybody also tell the
  agent to forget its clients of each person stopped (`dropSandboxClient`).

The lifecycle hooks (`webapp/src/lib/sandbox/lifecycle.ts`):

| Event | What stops |
| :---- | :--------- |
| An access change (`onAccessReduced` in `webapp/src/lib/authz/revocation.ts`, a sharing-policy change) | each person's instances outside their fresh own and act-as lists; a person left with no allowed project, `last_project_deleted` |
| An account disabled or deleted | both views, always asked, so `account_deleted` also removes the output folders when nothing runs |
| A project deleted (`webapp/src/lib/projectTeardown.ts`, step `stop_sandboxes`) | every instance mounting it, before and after the row is deleted, then the workspace is purged |
| The emergency stop | every sandbox for a holder of `platform:emergency_stop`, else both views of the presser (reason `emergency`); never retried later, which would stop sandboxes started after the emergency |
| The operator's stop in the admin Operations view (`POST /api/admin/operations/sandboxes/stop`, with RBAC governance on; `platform:operations` and `platform:emergency_stop`, read fresh) | both views of the chosen person (reason `operator`) |

A hook answers within 15 s with a count or a code for its caller to record. A stop
that failed (the orchestrator down or slower than that) is kept and retried in the
background (from 30 s, backing off to 10 minutes), and at once when a later hook
reaches the orchestrator; each retry reads access again. The backstop
(`reconcileRunningSandboxes`, run by every RBAC sweep, `RBAC_SWEEP_INTERVAL`, 300 s
by default) checks again every person with a running sandbox, at most 200 per
sweep, so what no hook saw (a share that expired, a capability lost to a role
change, a retry a webapp restart forgot) converges within one sweep.

Internal routes, for the agent only (master key, listed in the internal-route
allowlist of `webapp/src/middleware.ts`), under
`webapp/src/app/api/internal/agent/sandbox/`:

| Route | Body | Does |
| :---- | :--- | :--- |
| `POST /api/internal/agent/sandbox/ensure` | `{userId, projectId?, wait?, actingAs?}` | ensure, with the checks above |
| `POST /api/internal/agent/sandbox/lease` | `{userId, instance, leaseId, kind}` | take or renew a lease, after the account check |
| `POST /api/internal/agent/sandbox/release` | `{userId, leaseId}` | release a lease (204) |
| `GET /api/internal/agent/sandbox/list` | none | the running and draining sandboxes, with hosts and tokens |

The user id in these bodies is asserted by the agent, which takes it from a verified
ticket, token or job; the routes re-check the account but cannot prove whom the
agent acts for. They widen nothing: the master key already reaches the agent's
`/kali/exec`, and scan containers carry `SCANNER_API_KEY`, which these routes refuse
(`webapp/src/lib/session.ts`). They never log a body or a token.

Browser routes:

- `GET /api/agent/sandbox/status` (permission `agent:sessions`): the signed-in
  effective person's own instances of the view they work in (`act_as` while acting
  as a member): `state`, `stop_at`, `stop_reason`, `warn`, never a token, host,
  instance or project hash. The Sessions panel shows from it, in the seventh hour,
  "Your Kali sandbox stops at HH:MM because it has not been used for 7 hours; use it
  to keep it running".
- The admin Operations view lists the running sandboxes (person, view, state,
  times; no host or token) in a "Kali sandboxes" table, each with a Stop button.

## 13. The agent

The agent routes every Kali call by **person**, never by tenant: the person is the
run's actor (`agentic/decision_check.py`), or the owner of the MCP token, the
terminal ticket, the triage run or the Tradecraft job that started the work. The
`act_as` view is used when the work is an admin acting as the person (a terminal
ticket with `act`, a triage run started under act-as, a chat run whose actor is
acting).

- **The router** (`agentic/sandbox_router.py`): `sandbox_user()` and
  `sandbox_view()` say whose sandbox and which view; `for_person(...)` binds them
  for work that is not a chat run, and an empty person binds "no person", never the
  surrounding run's. `acquire`/`release`/`using` hold a lease renewed every 30 s. A
  named view must be the work's own view, or the call is refused: who does the work
  decides the view, an argument never does.
- **A chat run** (`run_scope`) acquires its sandbox lazily: the first Kali tool call
  inside the run takes a `run` lease, so a run that uses no Kali tool starts no
  sandbox. Its Fireteam members share the run's handle. `current_handle(project_id)`
  hands out only the handle of this work's person and view. A background job the
  run spawns (`detach_run_scope`) takes its own `job` lease, since it outlives the
  run.
- **The executor** (`agentic/tools.py`) sends every system Kali tool call, on both
  execution paths (a single tool and a plan wave), to the run's person's sandbox:
  each person has their own client for the five MCP servers, cached per instance,
  with that instance's bearer token. A call whose sandbox has gone retires every
  handle on that instance, so the next call ensures again.
- **No fallback**: work with no person fails (`no_user`); a call is never sent to
  another person's sandbox, to the other view of the same person, or anywhere when
  the webapp gateway cannot be reached (`SandboxUnavailable("error")`).
- **Status events**: each `starting`, `ready` and `unavailable` goes to the status
  listeners with the person, view, lease kind, project and chat session. The chat
  WebSocket forwards to the drawer only the events of `run` leases of that socket's
  own run; a background job reports through its own job updates.
- **The hold watcher** (`agentic/sandbox_hold.py`) lists the running sandboxes every
  60 s and reads each one's sessions and tunnels at once (5 s each). An instance
  holding a session, a job, a listener or an active tunnel gets one `hold` lease
  under a fixed id per instance (a restarted agent renews the same lease), renewed
  every 30 s while its last good read is at most 90 s old; a failed read justifies
  nothing. A tunnel counts only when this agent process pushed it (it reads the
  tunnel with the token of its own push), so after an agent restart a sandbox held
  by nothing but its tunnel stops after the idle minutes, until the next push. The
  hold is taken on the lease route, never through `ensure`, which would count as use.
- **Bounded reads** (`agentic/sandbox_http.py`): whoever is root in a sandbox writes
  its answers, so every read of a sandbox's own servers asks for an uncompressed
  answer, refuses any other encoding, stops at 1 MiB and at a 5 s deadline.
- **Stopping a run** (`agentic/sandbox_runs.py`): the processes a stopped chat run
  started are killed in each sandbox the run used, each asked with its own bearer;
  a run key is never sent to another person's sandbox. The emergency stop asks every
  running sandbox, each for at most 5 s.
- **Triage and Tradecraft**: triage's `cve_intel` runs in the sandbox of the person
  who started the triage; Tradecraft's browser tier renders in the sandbox of the
  person bound to the work. No person, no browser: a page is never rendered in
  someone else's sandbox.

Agent routes:

| Route | Behaviour |
| :---- | :-------- |
| `POST /kali/exec` | the body carries `user_id` (the MCP token's owner), required (400 `invalid_user_id`, answered before the gateway is asked anything); the job runs in that person's own view on an `exec` lease; when the sandbox is not running, the job is created at once with `status: "starting"` |
| `GET /kali/exec/{job_id}`, `POST .../cancel` | show `starting` while the job waits for the sandbox, and an `error_code` on a sandbox failure |
| `GET /sessions` | asks every running and draining sandbox at once (5 s each) and never starts one; every row carries `sandbox: <instance>` and the agent's own `sandbox_user` and `sandbox_view` tags (a sandbox cannot claim another's), rows of another id shape are dropped, at most 500 per list per sandbox, and `unavailable` names the sandboxes that did not answer; 503 `sandbox_list_unavailable` when the list itself cannot be read |
| `POST /sessions/{id}/interact`, `/sessions/{id}/kill`, `/jobs/{id}/kill`, `/session-chat-map`, `/non-msf-sessions` | take `?sandbox=<instance>` (required: 400 `sandbox_required`), optionally `?sandbox_user=` and `?sandbox_view=`; a malformed value (`shared` included) is 400 `invalid_sandbox`, an instance no running sandbox has is 404 `unknown_instance`, two matches are 409 `sandbox_ambiguous`. An interaction holds a short `interact` lease on that instance; a drive never starts a sandbox |
| `GET /tunnel-status` | requires the master key and `?user_id=` (400 `invalid_user_id`); answers `{ngrok, chisel}`, each `{active, host, port}`, for that person's current `own` instance, inactive when none runs (502 `tunnel_status_unavailable` when its tunnel manager does not answer), and never starts one |
| `WS /ws/kali-terminal` | routes to the ticket's `sub` (the `act_as` view when the ticket carries `act`) on a `terminal` lease; on a cold start it sends a `starting` frame and keeps what the browser sends (at most 64 KiB, else close 1009) for the shell; it forwards the sandbox's frames as bytes only, so the only text frames are its own `sandbox_status` frames |
| `POST /sandboxes/{user_id}/drop` | forget every client and handle of the person, both views; `{ok: true}` |
| `POST /sandboxes/{user_id}/tunnel` | body `{ngrokAuthtoken, chiselServerUrl, chiselAuth}`. A config that starts a tunnel acquires the person's `own` view (`interact`), posts it with the instance's tunnel token and answers `{ok, ngrok, chisel}` (502 `tunnel_push_failed` when the tunnel manager does not take it or the sandbox gave no tunnel token; a sandbox refusal is 403, 409 or 503 `sandbox_<reason>`); an empty config stops the tunnels of every `own` instance, draining ones included, with no `ensure` and no lease (`{ok, stopped}`, or 502 `tunnel_stop_incomplete` naming the ones that did not confirm) |
| `POST /emergency-stop-all` | also stops the runs in every running sandbox, before the webapp stops the sandboxes themselves |

## 14. Events and messages

| Where | Shape |
| :---- | :---- |
| Agent WebSocket | event `sandbox_status`, payload `{state: "starting" \| "ready" \| "unavailable", reason?: "ram" \| "hard" \| "error" \| "refused" \| "stopped", detail?, limit?}` (the limit is the governor payload). Sent, never stored. The drawer counts these frames only during a run, clears its status line when a run starts, and a Retry re-sends only once the run is over |
| Tool result to the model | `sandbox unavailable: not enough memory`; `sandbox unavailable: the instance's sandbox limit is reached`; `sandbox unavailable: the sandbox could not start`; `sandbox unavailable: this person may not use the Kali sandbox on this project`; `sandbox stopped during the call` |
| Terminal socket | a frame `{"type": "sandbox_status", "state": "starting"}`; on a memory or limit refusal a frame with `state: "unavailable"`, the reason and the limit, then close code 1013; on `refused` the same frame, then close code 1008. The terminal reads status frames only before the shell's first output, and treats 1013 and 1008 as sandbox closes only after an `unavailable` frame |
| MCP `kali_exec`, `kali_output` | status `starting`; `error_code` one of `ram`, `hard`, `sandbox_error`, `sandbox_refused`, `sandbox_stopped`, each with a note on what the caller can do (`webapp/src/lib/mcp/kaliTools.ts`) |
| Share dialog, "Use AI agent" and "Exploitation & shells" | "This person's agent runs on this project use your WPScan, URLScan and ProjectDiscovery keys inside a Kali sandbox, where this person can read them while their runs use them." |
| Modal in the terminal and the chat drawer | "Not enough memory" (or "Sandbox limit reached") with the figures in GB, buttons Retry and Close; "Kali sandbox could not start" and "Kali sandbox stopped", Retry and Close; "Kali sandbox not available" for a refusal, with a single button that closes it. A refused warm-up shows nothing |
| Sessions panel and the admin Operations view | "N sandboxes did not answer; their sessions may be out of date or missing" above the list when some did not answer, never an error page. A busy sandbox's rows from an earlier answer stay listed, marked "not refreshed", for up to a minute |

## 15. Environment variables

Every variable is optional, absent from `.env` by default, read by the
orchestrator only (through its compose `environment:` block), with its default in
code. A single-host deploy forwards the three `KALI_SANDBOX_*` knobs from the
operator's deploy settings and writes each into the server's `.env` only when it is
set.

| Variable | Default | Effect |
| :------- | :------ | :----- |
| `KALI_SANDBOX_IDLE_MINUTES` | 20 | minutes without use before an idle sandbox stops; an integer of at least 1, anything else is 20 |
| `KALI_SANDBOX_MAX_CONCURRENT` | unset: no count limit | the most running sandboxes; `0` blocks every new sandbox; anything but an integer of at least 0 is no limit. Advised on a server many people share |
| `KALI_SANDBOX_PORT_POOL` | unset: no pool | `[bind-ip:]first-last`: each sandbox gets one host port from the range for direct reverse shells, bound on `127.0.0.1` unless an address is given. A port the sandbox serves itself (8000, 8002-8005, 8013-8016, 4040), 4444 (so a reverse port of 4444 always means no pool port) or one another sandbox holds is never picked; a port the host already uses is tried once more with another and skipped for 10 minutes; a full pool starts a sandbox without one. A malformed value is no pool, and is logged |
| `TERMINAL_MAX_SESSIONS` | 5 (the terminal server's own) | copied into each sandbox: the most terminal sessions in one person's sandbox |

Not variables: the image, the lease timings, the 8-hour and 1-hour figures, the
template refresh period, the subnet range and the per-sandbox limits. The envelope
is a resource-profile value. `KALI_MEM`, `KALI_PIDS` and `KALI_CPUS` are ignored.

## 16. Timings

| Name | Seconds |
| :--- | ------: |
| Lease lifetime | 90 |
| Lease renewal | 30 |
| Idle stop (default) | 1 200 |
| Idle check | 60 |
| Hold without use, maximum | 28 800 |
| Warning before that | 3 600 |
| Agent hold watcher: listing, renewal | 60, 30 |
| Stop grace | 10 |
| Start timeout | 300 |
| A start that never settled, stopped after | 360 (start timeout + 60) |
| Adoption grace (no stop for holding no lease) | 90 |
| Templates refresh, retry after a failure | 86 400, 3 600 |
| Agent's wait on the webapp for `ensure` | 330 (start timeout + 30) |
| Agent's wait on the webapp, other calls | 10 |
| Webapp's wait on the orchestrator for a waiting `ensure` | 315 (start timeout + 15) |
| Each sandbox asked by a fan-out (`/sessions`, the hold watcher, stopping all runs) | 5 |
| A webapp lifecycle hook's answer | 15 |

Each layer waits longer than the one below it, so the orchestrator answers a slow
start before the webapp gives up, and the webapp before the agent does. A cold start
takes a few seconds; the first Metasploit call in a fresh sandbox waits another
15-18 s while `msfconsole` loads.

## 17. Tunnels and reverse shells

- Each sandbox runs its own tunnel manager on 8015. Starting a tunnel takes the
  instance's tunnel token; reading the status or stopping the tunnels also accepts
  the instance's MCP token, which the agent holds for every listed sandbox.
- A person's tunnel is their own: their settings (`tunnelsEnabled`,
  `ngrokAuthtoken`, `chiselServerUrl`, `chiselAuth`), set in Global Settings >
  Tunneling with the permission `platform:tunnels`, are pushed by the webapp
  through the agent (`pushSandboxTunnel`, `POST /sandboxes/{user_id}/tunnel`) to
  their own view's sandbox. A save that turns a tunnel on starts the sandbox first,
  so that start cannot reset the setting after the push. An empty configuration
  stops the tunnel.
- While acting as another account, a tunnel cannot be turned on or changed (it
  would run in that account's own sandbox, not the `act_as` one); turning it off
  is allowed. The `act_as` view has no tunnel.
- A freshly started sandbox has no tunnel, and the webapp turns the person's
  `tunnelsEnabled` off at that start, so a tunnel never comes back silently. A
  stored "on" whose sandbox runs no tunnel outlived a start whose reset was lost: it
  is turned off and the person is told, never pushed.
- When a view gets a new instance, the tunnels of its draining instance are turned
  off (a detached call inside it, sent again every idle tick while it drains); a
  drain with no replacement yet keeps its tunnel, so sessions that came in through
  it live on.
- The agent's lookups read the person's own tunnel: its status through
  `/tunnel-status?user_id=`, and the chisel settings through
  `/api/global/tunnel-config?userId=`, which answers that person's own row while
  their tunnel is on and nothing otherwise. The instance-wide tunnel fields of the
  admin instance settings reach no sandbox.
- The hold watcher keeps a sandbox with an active tunnel (section 13), for at most
  8 hours without use, when this agent process pushed that tunnel: after an agent
  restart a sandbox held only by its tunnel stops after the idle minutes.
- The reverse-shell listener inside the container is `MSF_REVERSE_PORT` (the pool
  port, or 4444). It is reachable from outside only through the person's tunnel, or
  through the pool port when one is set. The agent's LHOST/LPORT hints follow: with
  a tunnel, its address; with a pool port, that port as LPORT and the host's
  address the target can reach as LHOST; with neither, no direct reverse shell
  (a tunnel or a bind payload).
- On a single-host deploy (`tooling/deploy/single-host/deploy.sh`) the pool must be
  bound on `127.0.0.1` (or name no address), start at 1024 or above, hold at most
  100 ports and cover no port the host already serves; any other pool is refused.
  `revshell-open` then runs one forwarder per pool port (`redamon-revshell-<port>`,
  the host's address to `127.0.0.1:<port>`) and opens the range in the firewall for
  each target range only; without a pool it refuses and points to per-person
  tunnels. Each person's LPORT is their sandbox's pool port. `revshell-close` stops
  every forwarder and removes the rules, those an older release opened for 4444
  included.

## 18. Keeping the tools current

- **Nuclei templates** live in the named volume `redamon-kali-nuclei-templates`,
  mounted read-only in every sandbox; nuclei runs normally against read-only
  templates and never updates them during a scan. Before each start the
  orchestrator makes the volume when missing and fills it from the image (a short
  `redamon-kali-templates-populate-*` container; Docker copies the image's
  templates into an empty volume). On orchestrator start, and then daily, it
  refreshes them when the volume is missing, empty or a day old: the refresher
  container `redamon-kali-templates-refresh` (Docker's default bridge, never a
  sandbox network, no environment of its own, 512 MB, bounded to about 15 minutes
  inside and out) installs the latest templates release and only then writes the
  time into the volume, which a short `redamon-kali-templates-probe-*` container
  reads. A failed or skipped refresh is tried again an hour later. A refresher of
  this stack still running within its deadline is left to finish; any other
  container holding that name is never touched, and the refresh waits. A sandbox
  starts whatever the state of its templates.
- **Metasploit modules** ship with the image. Its last layers upgrade the
  `metasploit-framework` package when it is built with the build argument
  `MSF_REFRESH_STAMP`, recorded in the image label `redamon.msf_refresh`;
  a completed `./redamon.sh update` (not `--preview`) rebuilds them with the day's
  date, normally once a day, never writing
  the stamp to `.env`, and a failed refresh build only warns. Running sandboxes
  drain onto the new image (section 9).
- Packages a shell installs at run time are lost at the next stop.

## 19. Known limits

- **Shared projects are shared live.** A collaborator whose share holds "Use AI
  agent" or "Exploitation & shells" mounts the project folder read-write in their
  own sandbox, and the owner's WPScan, URLScan and ProjectDiscovery keys reach that
  sandbox while the collaborator's runs use them (the share dialog says so).
- **An MCP token's project limits do not confine the sandbox.** `kali_exec` runs in
  the token owner's own sandbox, which mounts every project that person may use
  with the agent, shared ones included, whether or not the token was minted with
  shared projects or a project allowlist.
- **No agent permission, no sandbox.** An account without `agent:chat`,
  `agent:kali_exec` or `platform:kali_terminal` (such as one that holds only
  `triage:run` or only `self:tradecraft`) gets none: a triage run it starts ranks
  findings on class priors without CVE intel, and Tradecraft renders its pages
  without the browser tier.
- **The read-only mounts are the same for everybody**: the MCP server code, the
  graph library, the nuclei templates volume, the OSV database and the custom
  nuclei templates folder, which holds every member's uploaded templates.
- **Aggregate CPU.** Each sandbox's CPUs and processes are capped and weighted below
  the services, but how many sandboxes run is bounded only by memory admission and
  `KALI_SANDBOX_MAX_CONCURRENT`.
- **Labs.** A guinea-pig lab is not on any sandbox network: connect it to a
  person's network for a test (`docker network connect redamon-sbx-<key> <lab>`, or
  `bash tests/kali_sandbox_isolation_live.sh --connect-lab <container> --as
  alice|bob` for the seeded accounts). The network's removal at that person's last
  stop disconnects it.
- **State lasts as long as the sandbox.** `/tmp`, installed packages, Metasploit
  sessions and tunnels end when the sandbox stops (20 idle minutes, 8 hours of a
  hold without use, an access loss, an emergency stop).
- A container escape is outside what these sandboxes defend against.

## 20. Tests

| Test | What it checks |
| :--- | :------------- |
| `tests/test_sandbox_contract.py` | the three contract copies agree, and the pure rules keep persons apart |
| `recon_orchestrator/tests/test_sandbox_*.py` | the manager, leases, routes, admission and templates |
| `agentic/tests/test_sandbox_*.py` | the router, the executor's routing, the agent's routes, the hold watcher |
| `webapp/src/lib/sandbox/*.test.ts`, `webapp/src/app/api/internal/agent/sandbox/sandboxRoutes.test.ts` | the gateway, the lifecycle hooks, the internal routes |
| `tests/kali_sandbox_guests_test.sh`, `tests/kali_sandbox_no_required_env_test.sh`, `tests/kali_sandbox_cleanup_test.sh`, `tests/kali_sandbox_removed_test.sh` | the guests forward nothing and the proxy refuses the pool; no variable became required; `./redamon.sh` removes and lists the sandboxes; no shared Kali service, address or port is left |
| `tests/kali_sandbox_isolation_live.sh` (live, after `python3 tests/kali_sandbox_seed_live.py`) | one check per threat between two seeded persons through MCP `kali_exec`, with `docker inspect` and `docker exec` as ground truth |
| `bash testing/e2e/scripts/per-user-sandbox-e2e.sh` (live, Playwright) | `testing/e2e/tests/perUserSandbox.spec.ts`: everything people do with the Kali tools from the UI, per person |

## 21. Roll-back

There is no switch back to a shared container. Rolling back means reverting the
commits that removed the shared Kali service and the per-user switch, rebuilding
the images they change (`docker compose build agent webapp && docker compose
--profile tools build kali-sandbox`) and running `./redamon.sh up` (the
orchestrator's source is mounted, so its recreate loads the reverted code).
`./redamon.sh update` does that by itself only for a published release that
carries the revert: after a local revert it has nothing to pull and recreates the
services on the images they have, and a webapp still on this release refuses the
reverted orchestrator's `{"mode": "shared"}` answer (503). With the revert in
place, the shared `redamon-kali` container and the `KALI_SANDBOX_MODE` switch come
back, per-user still the default. Then
`KALI_SANDBOX_MODE=shared` sends every Kali call to the shared container, and
per-user instances still running stop as they go idle. Locally, add it to `.env`
and run `./redamon.sh up` (it recreates the orchestrator with the new value; a
restart does not read `.env` again). On a single-host deploy, add it to the
application `.env` on the server and run `./deploy.sh update`: a plain
`./redamon.sh up` there leaves out the deploy's compose overlay and publishes the
stack's ports on every interface.

Every roll-back to the shared container gives up the separation this page
describes: one container, one set of tokens and one network for everybody again.
It mounts the whole agent workspace and the whole `mcp/output`, so every person's
output folder (`mcp/output/users/<key>`) becomes readable and writable from any
shell in it.

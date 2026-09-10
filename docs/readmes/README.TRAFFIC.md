# HTTP Traffic Capture

RedAmon's built-in, engagement-scoped **proxy history**: a man-in-the-middle proxy
that sits between every offensive tool and its target, records the full
request/response of each HTTP transaction, tags it with *who* produced it
(project / user / run / tool), stores it in Postgres, and exposes it to both the
human (the `/traffic` UI) and the AI agent (read-only `proxy_*` tools).

Think of it as an always-on HTTP history, except it is automatic (no manual proxy
config), attributed (every row knows which scan run and which agent session
created it), and queryable by the LLM itself.

> **Status:** shipped on branch `feat-remove_tor_integrate_mitmproxy`. Phase 0
> (direct httpx body ingest), Phase 1 (credential-free proxy + ingest), Phase 2
> (UI, export, delete, GC, body offload), part of Phase 3 (body search), plus
> agent-side replay + fuzz are live.
>
> Not yet wired (schema/comment stubs only): the `pg_trgm` full-text index (body
> search currently runs as `ILIKE`); the `labels`, `findingId` and `flowRef`
> columns (you cannot yet tag a transaction, link it to a finding, or do
> byte-perfect flow replay); and an automatic trigger for the `maintenance`
> retention job (the endpoint exists but nothing in the repo schedules it).

---

## Table of contents

- [1. The one idea to hold on to](#1-the-one-idea-to-hold-on-to)
- [2. Component inventory](#2-component-inventory)
- [3. End-to-end data flow](#3-end-to-end-data-flow)
- [4. Stage 1: Producers and the signed context tag](#4-stage-1-producers-and-the-signed-context-tag)
- [5. Stage 2: The capture proxy](#5-stage-2-the-capture-proxy)
- [6. Stage 3: The append-only spool](#6-stage-3-the-append-only-spool)
- [7. Stage 4: The ingest worker](#7-stage-4-the-ingest-worker)
- [8. Stage 5: Storage](#8-stage-5-storage)
- [9. Stage 6: Consumers](#9-stage-6-consumers)
- [10. Security model and trust boundaries](#10-security-model-and-trust-boundaries)
- [11. Configuration and lifecycle](#11-configuration-and-lifecycle)
- [12. Failure modes](#12-failure-modes)
- [13. Agent tools leveraging Traffic](#13-agent-tools-leveraging-traffic)

---

## 1. The one idea to hold on to

**Trust increases from left to right, and tenant identity is stamped at the trust
boundary.**

The proxy talks to attacker-controlled targets, so it is the *least-trusted*
component and holds nothing: no database credential, no signing key. Yet it
produces the data that everything downstream relies on. The whole architecture
exists to resolve that tension. Every unusual decision below (the spool hop, one
image running as two containers, the IP pin, drop-and-count backpressure, the
INSERT-only database role, inert body rendering, the constrained query builder)
is that single principle applied at one more layer.

Identity is carried across the untrusted zone as an opaque **signed capability**
(the `X-Redamon-Ctx` tag). The first component that can be trusted (the ingest
worker) verifies that signature and only then does `user_id` / `project_id`
become authoritative. Nothing a target ever touched is trusted to name a tenant.

---

## 2. Component inventory

| Component | Container | Network | Holds secret? | Source |
|---|---|---|---|---|
| Capture proxy | `redamon-capture-proxy` | `pentest-net` only | No | [`scanners/capture_proxy/capture_addon.py`](../../scanners/capture_proxy/capture_addon.py) |
| Ingest worker | `redamon-traffic-ingest` | `redamon` only | Yes (scoped DB role) | [`scanners/capture_proxy/ingest_worker.py`](../../scanners/capture_proxy/ingest_worker.py) |
| Tag primitive | (library, 3 copies) | n/a | key held by minters only | [`scanners/capture_proxy/redamon_ctx.py`](../../scanners/capture_proxy/redamon_ctx.py) |
| Egress guard | (library, in proxy) | n/a | No | [`scanners/capture_proxy/egress.py`](../../scanners/capture_proxy/egress.py) |
| Record shaping | (library, in proxy) | n/a | No | [`scanners/capture_proxy/capture_lib.py`](../../scanners/capture_proxy/capture_lib.py) |
| Orchestrator control | `recon-orchestrator` | `redamon` + `pentest-net` | Yes | [`recon_orchestrator/container_manager.py:968`](../../recon_orchestrator/container_manager.py#L968) |
| UI + API | `webapp` | `redamon` | Yes (full DSN) | [`webapp/src/app/traffic/`](../../webapp/src/app/traffic/) |
| Agent tools | `agent` | `redamon` | Yes (full DSN) | [`agentic/traffic_tools.py`](../../agentic/traffic_tools.py) |

**One image, two roles.** The proxy and the ingest worker are the *same*
`redamon-capture-proxy:latest` image ([`scanners/capture_proxy/Dockerfile`](../../scanners/capture_proxy/Dockerfile)).
The role is chosen at runtime by `command` + `network` + `env`, not by the image.
Isolation therefore comes entirely from *placement*: the proxy is put on the
target-facing network with no credentials; the ingest worker is put on the
internal network with a scoped role. They share only code.

**Base image:** `python:3.12-slim` (Debian slim). Only two pip installs:
`mitmproxy~=11.1` (the interception engine, used by the proxy role) and
`psycopg[binary]~=3.2` (Postgres driver, used only by the ingest role and unusable
in the proxy since it has no route to Postgres and no credential). Everything else
is Python stdlib.

**Persistent volumes:**

- `redamon_capture_spool` -> `/spool` : the append-only handoff between proxy and ingest.
- `redamon_capture_bodies` -> `/bodies` : content-addressed body blob store (shared with the webapp for read + GC).
- `redamon_capture_ca` -> `/ca` : the mitmproxy CA (a forge-anything private key, isolated to the proxy).

---

## 3. End-to-end data flow

```mermaid
flowchart LR
    subgraph untrusted["pentest-net (untrusted, no secrets)"]
        TOOL["offensive tool<br/>(katana, nuclei, curl,<br/>httpx, playwright...)"]
        PROXY["redamon-capture-proxy<br/>mitmdump + addon"]
        TARGET["target host<br/>(attacker-controlled)"]
    end

    subgraph handoff["shared volumes"]
        SPOOL[("/spool<br/>append-only *.json")]
        BODIES[("/bodies<br/>sha256 blobs")]
    end

    subgraph trusted["redamon-net (trusted)"]
        INGEST["redamon-traffic-ingest<br/>verify + stamp + insert"]
        PG[("Postgres<br/>captured_http_transactions")]
        WEBAPP["webapp /traffic UI"]
        AGENT["agent proxy_* tools"]
    end

    TOOL -->|"proxy flag +<br/>X-Redamon-Ctx tag"| PROXY
    PROXY -->|"tag stripped,<br/>IP-pinned"| TARGET
    TARGET -->|response| PROXY
    PROXY -->|metadata JSON| SPOOL
    PROXY -->|big/binary bodies| BODIES
    SPOOL -->|tail| INGEST
    INGEST -->|"verify HMAC,<br/>INSERT-only role"| PG
    BODIES -.->|ref by sha| PG
    PG --> WEBAPP
    PG --> AGENT
    BODIES -.->|read + GC| WEBAPP
```

The trusted zone is the only place `user_id` / `project_id` are treated as true.
Data crosses from the untrusted zone to the trusted zone through the spool,
carrying the tenant claim in a signed but as-yet-unverified form.

---

## 4. Stage 1: Producers and the signed context tag

Capture is **off by default** and controlled by a **two-level gate**
([`schema.prisma:129-142`](../../webapp/prisma/schema.prisma#L129-L142)):

1. **Global capability switch** `UserSettings.captureProxyEnabled` (operator-level).
   Flipping this is what actually spawns or stops the proxy + ingest containers
   via the orchestrator. If it is off, no capture container runs at all.
2. **Per-project routing gate** `Project.captureProxyEnabled` (the "HTTP Traffic
   Capture" toggle in the project form,
   [`TrafficCaptureSection.tsx`](../webapp/src/components/projects/ProjectForm/sections/TrafficCaptureSection.tsx)).
   This decides whether *that project's* traffic is routed through the running
   proxy.

Both must be on for a project to be captured. A third knob,
`UserSettings.captureProxyScope` (`recon | agent | both`, default `both`),
selects which producers route: recon tools, agent tools, or both.

When capture is active, two independent minters attach the tag, each holding a
*different* signing key.

### The tag

`X-Redamon-Ctx` is a compact, URL-safe, HMAC-SHA256 signed token
([`redamon_ctx.py:60`](../../scanners/capture_proxy/redamon_ctx.py#L60)). Format:
`<b64url(canonical-json)>.<b64url(hmac)>`. The JSON is canonical (sorted keys,
compact separators) so signer and verifier agree byte-for-byte, and only a
whitelist of fields is carried so a caller cannot smuggle extra fields past the
signature:

```
source, project_id, user_id, run_id, session_id, tool, phase, step, member_id
```

Valid `source` values are exactly `{"recon", "agent"}`.

### Two minters, two keys, one verifier

```mermaid
sequenceDiagram
    participant Recon as recon container
    participant Agent as agent / kali-sandbox
    participant Proxy as capture-proxy
    participant Ingest as traffic-ingest

    Note over Recon: holds SCANNER_API_KEY
    Note over Agent: holds INTERNAL_API_KEY
    Note over Proxy: holds NO key

    Recon->>Recon: sign_tag(source=recon, ...) with SCANNER_API_KEY
    Recon->>Proxy: request + X-Redamon-Ctx + proxy flag
    Agent->>Agent: sign_tag(source=agent, ...) with INTERNAL_API_KEY
    Agent->>Proxy: request + X-Redamon-Ctx + proxy flag

    Proxy->>Proxy: carry tag verbatim (cannot decode/forge)
    Proxy->>Ingest: (via spool) opaque tag + record

    Note over Ingest: holds BOTH keys
    Ingest->>Ingest: pick key by CLAIMED source, verify HMAC over whole body
    Ingest->>Ingest: derive tenant from VERIFIED claims only
```

Because `source` lives *inside* the signed body and the verifier selects its key
by that claimed source, an attacker who holds neither key cannot forge a tag for
either source. The proxy holds no key at all, so it can neither read nor forge the
tag; it only carries it.

**Recon minter** ([`recon/helpers/proxy_routing.py:104`](../../recon/helpers/proxy_routing.py#L104)):
`get_capture_routing(tool, phase)` signs with `SCANNER_API_KEY`, `source="recon"`,
carrying project/user/run IDs, tool, phase. Initialized once per run via
`proxy_routing.configure(settings)`.

**Agent minter** ([`agentic/tools.py:1780`](../../agentic/tools.py#L1780)):
`_build_redamon_ctx(tool_name)` signs with `INTERNAL_API_KEY`, `source="agent"`,
pulling project / user / session from ContextVars (never from LLM arguments). The
tag is injected as a stripped `_redamon_ctx` kwarg the model never sees.

### How each tool is pointed at the proxy

The proxy flag and the `-H X-Redamon-Ctx` header are always added **in the same
branch of code**. This is a deliberate leak-guard: the tag can never be attached
on the direct (non-proxy) path, so internal identifiers cannot leak to a target.

| Tool | Mechanism | Reaches proxy at |
|---|---|---|
| katana | `-proxy` + `-H` | `127.0.0.1:8888` (recon runs `--net=host`) |
| nuclei | `-proxy` + `-H` | same |
| ffuf | `-x` + `-H` | same |
| hakrawler | `-proxy` + `-H` | same |
| kiterunner | `--proxy` + `-H` | same |
| arjun | `HTTP_PROXY` env + `--headers` | same |
| agent curl | `-x` + `-H` | `redamon-capture-proxy:8888` (DNS) |
| agent httpx | `-proxy` + `-H` | same |
| agent playwright | launch `proxy={server}` + `extra_http_headers` (both wrapped and self-contained scripts) | same |
| agent nuclei | `-proxy` + `-H` | same |
| agent katana | `-proxy` + `-H` | same |
| agent ffuf | `-x` + `-H` | same |
| agent arjun | `HTTP_PROXY` env + `--headers` | same |
| agent wpscan | `--proxy` + `--headers` | same |

Eight agent tools are routed: `execute_curl`, `execute_httpx`,
`execute_playwright`, plus the HTTP recon/exploit tools `execute_nuclei`,
`execute_katana`, `execute_ffuf`, `execute_arjun`, `execute_wpscan`
(`_CAPTURE_ROUTED_TOOLS`, [`agentic/tools.py:63`](../../agentic/tools.py#L63)). These
mirror the recon pipeline so the agent's own crawl/fuzz/scan traffic is captured,
searchable, and replayable. For the `-H`-repeatable tools (nuclei/katana/ffuf) the
flag + header are appended like curl/httpx; `wpscan`/`arjun` merge the tag into a
single `--headers` value (arjun routes via `HTTP(S)_PROXY` env since it is
requests-based). Everything else the agent runs (subfinder, naabu, web_search,
query_graph, and so on) goes direct with no tag, by design.

**Inherent blind spot.** `kali_shell` (arbitrary `bash -c`), `execute_code`
(arbitrary interpreters), and `metasploit_console` HTTP modules run
attacker-defined commands, so no per-tool flag can force them through the proxy.
Closing this needs container-level transparent egress on the kali-sandbox plus a
default-identity tag, tracked as future hardening. Recon-side Python probes
(`security_checks`, cache-scan/WCVS, GraphQL, JS/AI-surface fetchers) and the
`ai_attack_surface_scan` container are likewise not yet routed.

### The Phase-0 side door

One producer bypasses the proxy entirely: the recon Python `httpx` probe
([`recon/helpers/traffic_capture.py`](../../recon/helpers/traffic_capture.py)). It
POSTs full transactions straight to the webapp ingest endpoint
`POST /api/traffic/{project_id}/ingest` with an `X-Internal-Key` header, and the
webapp stamps the tenant. This is the original Phase-0 path that retained httpx
bodies (otherwise discarded after fingerprinting) before the proxy existed. It
mints no `X-Redamon-Ctx` tag. So there are two ingest routes into the same table:
the proxy/spool path and this direct-POST path.

---

## 5. Stage 2: The capture proxy

`mitmdump -s capture_addon.py`, on `pentest-net` only, so it structurally cannot
reach Postgres, Neo4j, the agent, or the webapp. It runs with
`connection_strategy=lazy` (so the upstream connection is deferred until after the
request hook, which is what makes the IP pin below effective) and
`stream_large_bodies=5m` (bounds memory on huge responses).

```mermaid
flowchart TD
    START["request arrives"] --> LIFT["lift X-Redamon-Ctx onto flow metadata<br/>DELETE the header"]
    LIFT --> GUARD{"egress guard:<br/>resolve host,<br/>any internal IP?"}
    GUARD -->|"blocked or error"| B403["synthesize 403<br/>emit blocked=true record<br/>do NOT forward"]
    GUARD -->|allowed| PIN["pin server_conn.address<br/>to the vetted IP"]
    PIN --> FWD["forward to target<br/>(Host + SNI unchanged)"]
    FWD --> RESP["response returns"]
    RESP --> BUILD["assemble record<br/>inline vs offload bodies<br/>compute passive signals"]
    BUILD --> ENQ["enqueue to bounded queue"]
    ENQ -->|"queue full"| DROP["drop-and-count<br/>(never block proxy path)"]
    ENQ -->|space| WRITE["writer thread:<br/>write /spool/.tmp then os.replace"]
    B403 --> ENQ
```

### Request hook

1. **Strip the tag.** `headers.pop("X-Redamon-Ctx")` lifts the tag onto flow
   metadata and deletes the header so it never reaches the target
   ([`capture_addon.py:92`](../../scanners/capture_proxy/capture_addon.py#L92)).
2. **Egress guard** ([`egress.py`](../../scanners/capture_proxy/egress.py)). A new proxy is a
   new egress path, so it must not become an SSRF pivot into RedAmon's internal
   network. The guard resolves the hostname and refuses if *any* resolved A/AAAA
   address is internal: RFC1918, loopback, link-local, CGNAT `100.64.0.0/10`,
   reserved, multicast, unspecified, IPv4-mapped IPv6, or a configured blocked IP.
   A name resolving to one public + one internal address is treated as hostile.
   Every error path fails **closed** (unparseable IP, unresolvable name, bad IDNA
   label all block).

   **Configurable per condition.** Each block condition is an independent toggle
   in an [`EgressPolicy`](../../scanners/capture_proxy/egress.py), surfaced in *Global
   Settings > TrafficMind > Egress guard* and injected at proxy spawn as
   `CAPTURE_EGRESS_*` env (`policy_from_env`). **Every check defaults to block**,
   so `EgressPolicy()` reproduces the always-on guard and every existing caller /
   test is unchanged. An operator can relax one class, most usefully
   `block_private`, to let the proxy reach an internal / lab target on a private
   Docker network, *without* weakening the others, because each address class has
   its own independent check (relaxing RFC1918 does not un-block `127.0.0.1`, which
   is still caught by `block_loopback`). Two safety invariants hold regardless of
   the toggles: (a) the explicit `extra_blocked` IP denylist (`CAPTURE_BLOCKED_IPS`,
   RedAmon's own service IPs) is **never** policy-gated, so unblocking private
   targets cannot pivot into RedAmon itself; and (b) `check_egress` returns
   `allowed=True` only with a concrete pinned IP, so an empty / unresolvable host
   is never forwarded even if its toggle is off (the toggle only relabels the
   refusal). The `fail_closed_on_error` toggle governs the guard-internal-error
   path: on (default) an error blocks; off makes it fail-open (forward without
   vetting); exposed for completeness, but dangerous.
3. **IP pin.** On allow it sets `flow.server_conn.address` to the exact vetted IP,
   so mitmproxy does not re-resolve and land on a rebound internal address between
   the guard check and the connection (a DNS-rebinding TOCTOU). Only the
   connection address is pinned, not `request.host`, so the Host header and TLS
   SNI keep the original hostname and vhosts / HTTPS still work.
4. **Blocked requests** get a synthetic `403` and a `blocked=true` spool record.
   The attempt is still recorded, for the scope audit.

### Response hook

Assemble the record, decide inline vs offload per body, compute passive signals,
enqueue. Wrapped in a blanket exception handler that logs but never breaks the
proxy path.

**Body policy** ([`capture_lib.py:101`](../../scanners/capture_proxy/capture_lib.py#L101)). Each
body is routed to exactly one destination: **inline** (Postgres column, agent +
human readable), **disk** (offload to `/bodies/<sha256>`, human/UI readable only),
or **meta** (drop bytes, keep only size + sha256). The routing is a per
content-type **family** policy, not a flat text/binary split:

1. Master `store_bodies` off, empty body, or a per-direction toggle
   (`CAPTURE_STORE_REQ_BODIES` / `CAPTURE_STORE_RESP_BODIES`) off -> **meta**.
2. `classify_family` maps the `Content-Type` (with a URL filename-extension
   fallback that rescues octet-stream-mislabeled files, e.g. a `.woff2` served as
   `application/octet-stream`) to one of: `text json script image font video
   audio document archive binary other`.
3. The family's **policy** (`CAPTURE_BODY_RULES`, a JSON `family->policy` map
   merged over the shipped **Recommended** defaults) decides:
   - `auto` -> size-based: text-like family and size <= inline cap
     (`CAPTURE_PROXY_MAX_BODY_KB`, default 64 KB) -> **inline**, else **disk**.
   - `inline` -> force DB (falls back to disk over the inline cap).
   - `disk` -> always offload.
   - `meta` -> drop bytes, keep size + sha256.
4. A hard ceiling `CAPTURE_MAX_STORE_MB` (default 5 MB, 0 = unlimited) overrides
   `disk`/`inline` to **meta** for any oversized body.

Recommended defaults: text/json/script `auto`; image/font/video/audio `meta`
(render noise dropped); document/archive/binary `disk` (leak-worthy downloads
kept). Offload is content-addressed, so identical bodies dedup by sha256. The
`CAPTURE_PROXY_MAX_BODY_KB` cap is a DB-vs-disk **routing** threshold, never a
size limit — the only knob that *drops* by size is `CAPTURE_MAX_STORE_MB`.

**Passive signals**, computed for free on every response
([`capture_lib.py:85`](../../scanners/capture_proxy/capture_lib.py#L85)): `hadAuth`,
`hasSetCookie`, missing security headers, cookie-flag issues (missing
HttpOnly / Secure / SameSite), and `reflectedParams` (any query or body param value
of at least 4 characters appearing verbatim in the response body, a lead for XSS /
SSTI / open-redirect).

### Backpressure

A bounded `queue.Queue` (default 2000, `CAPTURE_QUEUE_MAX`) drained by a single
daemon writer thread. If the queue fills, the proxy **drops and counts** rather
than blocking the data path. Capture is best-effort: it must never slow a scan.

### Hardening

Non-root user (uid 10001), `read_only` root filesystem, `cap_drop: [ALL]`,
`mem_limit` 384m, `pids_limit` 256. Privilege escalation is blocked by stripping
setuid / setgid bits from every binary in the image
([`Dockerfile:19`](../../scanners/capture_proxy/Dockerfile#L19)) rather than the
`no-new-privileges` flag, which breaks `execve` for non-root users on this
project's snap-Docker / AppArmor hosts. The mitmproxy CA lives on its own volume
via `--set confdir=/ca` and its private key never leaves that volume.

---

## 6. Stage 3: The append-only spool

The spool is not a single appended file. It is a **directory with one atomically
renamed file per flow**, which keeps it concurrency-safe under many mitmproxy
coroutines and effectively append-only.

```mermaid
flowchart LR
    W["writer thread"] -->|"1. write full JSON"| TMP[("/spool/.tmp/<br/>ns-uuid.json")]
    TMP -->|"2. os.replace (atomic)"| FINAL[("/spool/<br/>ns-uuid.json")]
    FINAL -->|"3. sorted listdir"| I["ingest worker reads<br/>only COMPLETE files"]
    I -->|"4a. success"| DEL["os.unlink"]
    I -->|"4b. bad tag / bad row"| REJ[("/spool/.rejected/")]
```

The write ([`capture_addon.py:226`](../../scanners/capture_proxy/capture_addon.py#L226))
writes to `/spool/.tmp/` then `os.replace()` into `/spool/`. The rename is atomic
within the filesystem, so the ingest worker never sees a half-written record. The
filename is `time_ns()`-prefixed so a plain `sorted(os.listdir())` yields roughly
chronological processing order. Large / binary bodies are written to `/bodies`
with the same tmp-then-`os.replace` pattern and an existence check for dedup.

---

## 7. Stage 4: The ingest worker

[`ingest_worker.py`](../../scanners/capture_proxy/ingest_worker.py), on `redamon` only (no
target egress at all). It is the *only* capture component that holds a database
credential, and that credential is a role which can do exactly one thing: INSERT
into one table.

```mermaid
flowchart TD
    LIST["sorted(listdir /spool)"] --> LOAD{"parse JSON?"}
    LOAD -->|no| REJ["move to /spool/.rejected"]
    LOAD -->|yes| VERIFY{"verify_tag HMAC<br/>+ project_id + user_id present?"}
    VERIFY -->|invalid| REJ
    VERIFY -->|valid| STAMP["stamp tenant from VERIFIED payload<br/>everything else from untrusted record"]
    STAMP --> REDACT["redact sensitive headers<br/>(salted hash, correlatable)"]
    REDACT --> INS{"INSERT via scoped role"}
    INS -->|ok| DEL["os.unlink spool file"]
    INS -->|"permanent (DataError,<br/>Integrity, Programming)"| REJ
    INS -->|"transient (conn reset,<br/>deadlock, restart)"| RETRY["leave file, re-raise,<br/>reconnect + retry"]
```

Key properties:

- **Verification** ([`redamon_ctx.py:74`](../../scanners/capture_proxy/redamon_ctx.py#L74)):
  read `source` from the unverified body only to *select* the key, then
  `hmac.compare_digest` over the whole body (constant-time), then re-canonicalize
  and compare to reject any smuggled extra fields.
- **Tenant stamping** ([`ingest_worker.py:83`](../../scanners/capture_proxy/ingest_worker.py#L83)):
  `project_id`, `user_id`, `source` and attribution come from the *verified*
  payload. Everything else (method, host, bodies, signals) comes from the
  untrusted proxy record. The primary key `id` is generated here because Prisma's
  cuid default is client-side.
- **Redaction** ([`ingest_worker.py:53`](../../scanners/capture_proxy/ingest_worker.py#L53)):
  when `CAPTURE_PROXY_REDACT_SECRETS` is on, sensitive headers (authorization,
  cookie, set-cookie, x-api-key, x-auth-token, proxy-authorization) are replaced
  with `[redacted:<salted-hash-prefix>]`, so identical secrets still correlate
  without storing plaintext.
- **Retry discipline**: transient database errors leave the spool file in place
  and re-raise, so the outer loop reconnects and retries. A validly captured
  record is never discarded. Only permanent constraint errors get rejected.

### The scoped role

[`scanners/capture_proxy/sql/001_traffic_ingest_role.sql`](../../scanners/capture_proxy/sql/001_traffic_ingest_role.sql)
creates the `traffic_ingest` login role and grants it exactly:

```sql
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM traffic_ingest;
GRANT USAGE ON SCHEMA public TO traffic_ingest;              -- just to name the table
GRANT INSERT ON TABLE captured_http_transactions TO traffic_ingest;
REVOKE SELECT ON captured_http_transactions FROM traffic_ingest;  -- never read back
```

INSERT on one table, no SELECT, no other tables, no DDL. Even a fully compromised
ingest worker can only append non-readable, purgeable rows: it can neither
exfiltrate another tenant's data nor tamper with existing rows.

### Documented residual

The tag authenticates the tenant claims but has no nonce, no expiry and no binding
to request content. A fully compromised proxy therefore sees valid tags for the
tenants it proxies and could replay one to attribute *fabricated* rows to that
tenant. This is bounded by the INSERT-only role (forged rows are non-readable,
purgeable, and land only in a tenant whose traffic the proxy already saw) and is
the accepted price of keeping the proxy credential-free. Closing it fully would
need a content digest plus a short expiry in the tag (a future hardening).

---

## 8. Stage 5: Storage

Table `captured_http_transactions`, Prisma-owned
([`schema.prisma:1052`](../../webapp/prisma/schema.prisma#L1052)) so both the ingest
worker and the webapp agree on the shape. The ingest worker references the
snake_case column names directly.

Shape (grouped):

- **Tenancy:** `projectId`, `userId` (both `onDelete: Cascade`).
- **Attribution:** `source` (recon|agent), `runId`, `sessionId`, `memberId`,
  `tool`, `phase`, `stepId`.
- **Request:** `method`, `scheme`, `host`, `port`, `path`, `query`, `reqHeaders`
  (Json), `reqBody` (inline text if small), `reqBodyRef` (sha256 -> disk),
  `reqBodySize`, `reqContentType`, `reqBodySha256`.
- **Response:** `statusCode`, `respHeaders`, `respBody`, `respBodyRef`,
  `respBodySize`, `respContentType`, `respBodySha256`, `responseTimeMs`.
- **Network:** `targetIp`, `httpVersion`, `isTls`, `tlsVersion`.
- **Replay lineage:** `isReplay`, `originId`. Populated when the agent replays or
  fuzzes a request (see section 13): the replayed transaction is re-captured with
  `isReplay = true` and `originId` pointing at the source transaction, both
  stamped from the *verified* replay tag.
- **Scope / safety:** `inScope`, `blocked`, `errorText`.
- **Secret handling:** `redacted`, `redactedFields`.
- **Passive signals:** `hasSetCookie`, `hadAuth`, `reflectedParams`,
  `securityHeadersMissing`, `cookieFlagIssues` (computed by the proxy only when
  `captureProxyPassiveDetect` is on).
- **Supply-chain incident match:** `iocIncidentId`, `iocIncidentUrl`. Set when
  the request's host or resolved IP appears in the offline incident catalog
  (see [README.SUPPLY_CHAIN.md](README.SUPPLY_CHAIN.md)). A local set lookup, no
  network and no new credential, so the worker's INSERT-only role is unchanged.
  **NULL means "no match OR the catalog was never synced" — never "this host is
  clean".** Both writers set them; see the warning below.
- **Timestamps:** `startedAt`, `createdAt`.
- **Reserved (declared but not yet wired):** `labels`, `findingId`, `flowRef`. No
  code writes or reads these today, so transaction tagging, finding links, and
  byte-perfect flow replay are not implemented; current replay rebuilds the
  request from the stored fields.

**Indexes:** ten composite btree indexes, every one prefixed by `projectId`
(`[projectId,userId]`, `[projectId,createdAt]`, `[projectId,source]`,
`[projectId,host]`, `[projectId,sessionId]`, `[projectId,runId]`,
`[projectId,tool]`, `[projectId,statusCode]`, `[projectId,isReplay]`,
`[projectId,inScope]`). There is no `pg_trgm` / tsvector index yet: body and URL
search currently run as `ILIKE` / `contains` with no supporting index.

Bodies are stored inline when small, otherwise offloaded to the content-addressed
blob store at `CAPTURE_BODIES_DIR` and referenced by sha256. Blob filenames are
validated against `^[0-9a-f]{64}$` to block path traversal
([`captureBodies.ts`](../../webapp/src/lib/captureBodies.ts)).

---

## 9. Stage 6: Consumers

### Human: the `/traffic` UI

[`webapp/src/app/traffic/page.tsx`](../../webapp/src/app/traffic/page.tsx). A
server-paginated, proxy-style table. Columns: Time, Source (recon/agent badge),
Tool, Method, Host, Path, Status (colored by class, "BLK" if blocked), Length,
response Time, Flags (cookie / reflect / replay / out-of-scope / **ioc**, which
links to the incident write-up when the catalog supplied a usable http(s) URL —
the link is scheme-checked at render because the feed is third-party). Filters: date
range, source, tool, host, method, status class, run, URL search (`q`), body
search (`bodyq`), set-cookie, 5xx-only. A detail drawer shows full request /
response with a client-side "Copy as curl" (`toCurl` in the page, distinct from
the agent SDK's `redamon.to_curl`). **Response bodies are rendered as inert text,
never HTML**, because they are attacker-controlled.

### API routes

All routes under [`webapp/src/app/api/traffic/`](../../webapp/src/app/api/traffic/)
enforce `requireEffectiveUser` + `requireProjectAccess`. Tenant fields always come
from the session / route, never the client.

- **`GET [projectId]`** : paginated filtered list. Summary columns only, bodies
  never in the list. Whitelisted `orderBy`, max page size 200. Shared predicate
  `buildTrafficWhere`.
- **`GET [projectId]/[id]`** : one full transaction incl. headers and bodies.
  `findFirst({id, projectId, ownerScope})`, so a cross-tenant id returns 404
  (anti-enumeration). Offloaded bodies resolved only through the owned row.
- **`GET [projectId]/export`** : streams the current filtered set as CSV or JSON,
  keyset-paginated, 50k-row cap with a truncation marker, CSV formula-injection
  guard.
- **`GET [projectId]/facets`** : distinct tool / host / runId / sessionId for the
  filter dropdowns.
- **`DELETE [projectId]`** : batch delete by ids or by filter (reusing
  `buildTrafficWhere` so "delete all matching" equals the current view). Collects
  the doomed rows' body refs, deletes, then ref-counted GC of orphaned blobs, then
  an audit log line.
- **`POST maintenance`** : internal-only (`isInternalRequest`). Three phases:
  per-owner retention purge using `UserSettings.captureProxyRetentionDays`
  (default 14, `<= 0` keeps forever), per-project quota eviction of the oldest
  beyond the `CAPTURE_PROXY_MAX_ROWS_PER_PROJECT` env (default 200000), and a full
  orphan-body sweep. **Caveat: nothing in the repo schedules this.** The endpoint
  is written to be driven by a cron or the orchestrator, but no cron, timer, or
  caller currently POSTs to it. Until one is wired, retention and quota eviction
  do not run and the corpus grows unbounded.
- **`POST [projectId]/ingest`** : the Phase-0 producer side (writer, see 4.4).

Body GC ([`captureBodies.ts`](../../webapp/src/lib/captureBodies.ts)) is ref-counted
across all tenants with a 5-minute grace window to avoid a TOCTOU against in-flight
ingest. Blobs are served only via an owned row, never by raw sha path.

### Agent: `proxy_brain`

Covered in full in [section 13](#13-agent-tools-leveraging-traffic).

---

## 10. Security model and trust boundaries

```mermaid
flowchart LR
    subgraph red["UNTRUSTED (talks to targets)"]
        direction TB
        P["capture-proxy<br/>no DB cred<br/>no signing key<br/>read-only rootfs<br/>cap_drop ALL"]
    end

    subgraph green["TRUSTED (internal net)"]
        direction TB
        I["traffic-ingest<br/>INSERT-only role<br/>no target egress"]
        R[("full DATABASE_URL<br/>webapp + agent")]
    end

    T["target"] <-->|"egress-guarded,<br/>IP-pinned"| P
    P ==>|"opaque signed tag<br/>via append-only spool"| I
    I -->|"verified tenant<br/>INSERT only"| R
```

Boundary-by-boundary:

1. **Proxy has no credentials and no key.** It cannot read the tenant name, forge
   a tag, reach Postgres, or read another tenant's traffic. A full proxy
   compromise yields only forged INSERT-only rows in already-seen tenants.
2. **The tag is a signed capability.** Two minters, two keys, one verifier;
   `source` inside the signed body; canonical JSON; constant-time compare. Forgery
   requires a key the proxy and targets never hold.
3. **Ingest is the trust boundary.** Tenant identity becomes authoritative only
   after HMAC verification, and even ingest can only INSERT one table.
4. **Egress guard + IP pin** stop the proxy from being an SSRF pivot or a
   DNS-rebinding hole into the internal network.
5. **Attacker-controlled bodies stay inert.** The UI renders bodies as text, and
   the agent tools never build raw SQL from body content (see section 13).
6. **Least-privilege containers.** Non-root, read-only rootfs, dropped caps,
   memory and pid limits on both the proxy and the ingest worker.

### Known residuals

- **Tag replay** by a fully compromised proxy (bounded by INSERT-only, see 7).
- **Spool is a shared read-write volume.** A compromised proxy could delete or
  overwrite spooled records before ingest reads them (lost capture data), a weaker
  property than the "append-only" name implies. The residual is lost evidence, not
  forged readable rows.
- **`/bodies` is chmod 0777** so the differently-uid'd webapp can read and GC it.
  Defensible (internal volume, never served by raw path) but a shared-gid approach
  would be tighter.

---

## 11. Configuration and lifecycle

### The toggle

The **global** switch `UserSettings.captureProxyEnabled` drives container
lifecycle. The trigger lives in the user-settings write
([`webapp/src/app/api/users/[id]/settings/route.ts:221`](../../webapp/src/app/api/users/[id]/settings/route.ts#L221)),
not in project save. It calls the orchestrator when the switch flips, or when a
runtime knob changes while it is already enabled.

```mermaid
sequenceDiagram
    participant UI as user settings save
    participant Orch as recon-orchestrator
    participant Docker as Docker API

    UI->>Orch: POST /capture-proxy/start {port, maxBodyKb, storeBodies, redactSecrets, scope}
    Orch->>Docker: run redamon-capture-proxy (redamon_pentest-net, 127.0.0.1:port, no creds)
    Orch->>Docker: run redamon-traffic-ingest (redamon-network, scoped DSN + verify keys)
    Orch-->>UI: capture_proxy_status()
    Note over UI,Orch: switch off -> POST /capture-proxy/stop -> stop + remove both
```

The orchestrator endpoints are `/capture-proxy/{start,stop,status}`
([`api.py:400`](../../recon_orchestrator/api.py#L400)); the spawn logic is
[`container_manager.py:968`](../../recon_orchestrator/container_manager.py#L968). It
spawns the pair idempotently. The image is taken from trusted orchestrator env
only and is never overridable from the UI, so the operator toggle can never spawn
an arbitrary image. The proxy is published on `127.0.0.1:<port>` so host-net recon
containers reach it; the ingest worker gets the scoped `TRAFFIC_INGEST_DATABASE_URL`
plus both verification keys. The settings write is best-effort (wrapped in
try/catch) so a save never fails just because the orchestrator is down.

Exact networks: the proxy joins `redamon_pentest-net` only
(`_CAPTURE_PROXY_NETWORK`), the ingest worker joins `redamon-network` only
(`_CAPTURE_INGEST_NETWORK`,
[`container_manager.py:942-943`](../../recon_orchestrator/container_manager.py#L942-L943)).

There is also a static `capture` compose profile
([`docker-compose.yml:889`](../../docker-compose.yml#L889)) that defines the same two
services for a manual `docker compose --profile capture up`.

### Settings (database fields)

These are per-owner / per-project settings, not env vars. The container-shaping
ones are pushed to the orchestrator on the settings save.

| Field | Model | Default | Purpose |
|---|---|---|---|
| `captureProxyEnabled` | UserSettings | false | global switch; spawns/stops containers |
| `captureProxyEnabled` | Project | false | per-project routing gate |
| `captureProxyScope` | UserSettings | `both` | which producers route (recon\|agent\|both) |
| `captureProxyPort` | UserSettings | 8888 | proxy listen + publish port |
| `captureProxyStoreBodies` | UserSettings | true | master switch: store bodies at all |
| `captureProxyStoreReqBodies` | UserSettings | true | store request bodies (direction gate) |
| `captureProxyStoreRespBodies` | UserSettings | true | store response bodies (direction gate) |
| `captureProxyMaxBodyKb` | UserSettings | 64 | inline (DB-vs-disk) text routing threshold |
| `captureProxyMaxStoreMb` | UserSettings | 5 | hard drop ceiling in MB (0 = unlimited) |
| `captureProxyBodyRules` | UserSettings | `{}` | per-family policy map (auto\|inline\|disk\|meta); `{}` = Recommended defaults |
| `captureProxyRedactSecrets` | UserSettings | true | redact sensitive headers |
| `captureProxyPassiveDetect` | UserSettings | true | compute passive signals |
| `captureProxyRetentionDays` | UserSettings | 14 | maintenance retention (`<= 0` = forever) |
| `captureEgressBlockEmptyHost` | UserSettings | true | egress guard: block empty Host |
| `captureEgressBlockHardGuardrail` | UserSettings | true | egress guard: block `.gov/.mil/.edu/.int` + denylist |
| `captureEgressFailClosed` | UserSettings | true | egress guard: fail closed on guard error (off = fail-open, dangerous) |
| `captureEgressBlockUnresolvable` | UserSettings | true | egress guard: block unresolvable / bad-IDNA hosts |
| `captureEgressBlockPrivate` | UserSettings | true | egress guard: block RFC1918 + IPv6 ULA (off = reach private/lab targets) |
| `captureEgressBlockLoopback` | UserSettings | true | egress guard: block `127.0.0.0/8`, `::1` |
| `captureEgressBlockLinkLocal` | UserSettings | true | egress guard: block `169.254.0.0/16` (incl. metadata), `fe80::/10` |
| `captureEgressBlockCgnat` | UserSettings | true | egress guard: block `100.64.0.0/10` |
| `captureEgressBlockReserved` | UserSettings | true | egress guard: block IANA-reserved ranges |
| `captureEgressBlockMulticast` | UserSettings | true | egress guard: block `224.0.0.0/4`, `ff00::/8` |
| `captureEgressBlockUnspecified` | UserSettings | true | egress guard: block `0.0.0.0`, `::` |
| `scaIntelIgnoreSuffixes` | UserSettings | the 5 OAST providers | hosts excluded from the supply-chain incident match |

`scaIntelIgnoreSuffixes` is per-USER, not per-project: an operator's OAST
provider is a property of their tooling, not of a target. The incident catalog
legitimately lists `oastify.com` and friends as indicators, so without this list
a pentester running an OAST server would flag their own callbacks on every
engagement. **Clearing the box restores the shipped list rather than disabling
suppression** — to see OAST hits, replace it with a host you never use. It
reaches the ingest worker as `CAPTURE_IOC_IGNORE_SUFFIXES` via the same
capture-config reconciler that carries the egress policy, because the worker
holds no credential that could read it from the database.

> **Both writers must set the IOC columns.** `captured_http_transactions` has
> two writers — the Python spool worker (`build_row`) and the webapp's direct
> ingest route — and if only one of them flagged, an operator would see some
> requests marked and reasonably conclude the unmarked ones had been checked and
> cleared. A shared case table is duplicated in `tests/test_sca_ioc_match.py`
> and `webapp/src/lib/scaIntel.test.ts`; changing one side alone turns the other
> red. Note this breaks transiently during a deploy that restarts the two
> services at different times.

The eleven `captureEgress*` fields are pushed to the orchestrator on save (as the
`egress*` keys of `CaptureProxyConfig`) and injected into the spawned proxy as the
`CAPTURE_EGRESS_*` env below. All default **true** (block).

### Environment variables

| Variable | Default | Applies to | Purpose |
|---|---|---|---|
| `CAPTURE_PROXY_ENABLED` | false | producers | routing gate (derived from `Project.captureProxyEnabled`) |
| `CAPTURE_PROXY_IMAGE` | `redamon-capture-proxy:latest` | orchestrator | image (trusted env only) |
| `CAPTURE_PROXY_MAX_BODY_KB` | 64 | proxy | inline (DB-vs-disk) text routing threshold |
| `CAPTURE_PROXY_STORE_BODIES` | true | proxy | master switch: store bodies at all |
| `CAPTURE_STORE_REQ_BODIES` | true | proxy | store request bodies (direction gate) |
| `CAPTURE_STORE_RESP_BODIES` | true | proxy | store response bodies (direction gate) |
| `CAPTURE_MAX_STORE_MB` | 5 | proxy | hard drop ceiling in MB (0 = unlimited) |
| `CAPTURE_BODY_RULES` | (empty) | proxy | JSON family->policy map; empty = Recommended defaults |
| `CAPTURE_PROXY_REDACT_SECRETS` | true | ingest | redact sensitive headers |
| `CAPTURE_REDACT_SALT` | `redamon-capture` | ingest | salt for redaction hash |
| `CAPTURE_BLOCKED_IPS` | (empty) | proxy | extra egress denylist (**always enforced**, never policy-gated) |
| `CAPTURE_EGRESS_BLOCK_EMPTY_HOST` | true | proxy | egress guard: block empty Host |
| `CAPTURE_EGRESS_BLOCK_HARD_GUARDRAIL` | true | proxy | egress guard: block `.gov/.mil/.edu/.int` + denylist |
| `CAPTURE_EGRESS_FAIL_CLOSED` | true | proxy | egress guard: fail closed on guard error (false = fail-open) |
| `CAPTURE_EGRESS_BLOCK_UNRESOLVABLE` | true | proxy | egress guard: block unresolvable / bad-IDNA |
| `CAPTURE_EGRESS_BLOCK_PRIVATE` | true | proxy | egress guard: block RFC1918 + IPv6 ULA |
| `CAPTURE_EGRESS_BLOCK_LOOPBACK` | true | proxy | egress guard: block loopback |
| `CAPTURE_EGRESS_BLOCK_LINK_LOCAL` | true | proxy | egress guard: block link-local (incl. metadata) |
| `CAPTURE_EGRESS_BLOCK_CGNAT` | true | proxy | egress guard: block CGNAT `100.64/10` |
| `CAPTURE_EGRESS_BLOCK_RESERVED` | true | proxy | egress guard: block reserved ranges |
| `CAPTURE_EGRESS_BLOCK_MULTICAST` | true | proxy | egress guard: block multicast |
| `CAPTURE_EGRESS_BLOCK_UNSPECIFIED` | true | proxy | egress guard: block `0.0.0.0` / `::` |
| `CAPTURE_QUEUE_MAX` | 2000 | proxy | backpressure queue size |
| `CAPTURE_PROXY_MAX_ROWS_PER_PROJECT` | 200000 | maintenance | per-project quota eviction |
| `TRAFFIC_INGEST_DATABASE_URL` | (empty) | ingest | scoped INSERT-only DSN |
| `SCANNER_API_KEY` | changeme | recon minter + ingest verify | recon-source key |
| `INTERNAL_API_KEY` | (env) | agent minter + ingest verify | agent-source key |
| `CAPTURE_PROXY_MEM` | 384m | proxy | proxy memory limit |
| `TRAFFIC_INGEST_MEM` | 256m | ingest | ingest memory limit |

There is no `CAPTURE_PROXY_RETENTION_DAYS` or `CAPTURE_PROXY_SCOPE` env var:
retention and scope are the database fields above.

### First-time setup

1. `docker compose exec webapp npx prisma db push` to create the table.
2. Apply the scoped role once:
   `docker compose exec -T postgres psql -U redamon -d redamon -v role_password="'<secret>'" -f - < scanners/capture_proxy/sql/001_traffic_ingest_role.sql`
3. Set `TRAFFIC_INGEST_DATABASE_URL=postgresql://traffic_ingest:<secret>@postgres:5432/redamon`.
4. Build the image: `docker compose --profile capture build capture-proxy`.
5. Enable the per-project toggle.

---

## 12. Failure modes

- **Proxy unreachable while capture is enabled:** both recon and agent producers
  TCP-probe reachability (recon with a 15s re-probe TTL). If enabled but
  unreachable, the tool runs **direct, with no tag**, and logs it. The consequence
  is a *silent evidence gap*, never a scan failure. On this direct path the tag
  header is provably never attached (flag + header are always added together).
- **Spool backs up:** the proxy drops and counts; the proxy data path never
  blocks.
- **Bad / missing / forged tag:** the ingest worker moves the record to
  `/spool/.rejected`; it is never inserted.
- **Transient DB error:** ingest leaves the spool file and retries; no capture is
  lost.
- **Permanent constraint error:** ingest rejects that one record and continues.
- **Body offloaded but not readable agent-side:** `redamon.get` returns
  `[offloaded to disk - not available agent-side]` rather than failing.

---

## 13. Agent tools leveraging Traffic

The agent works the capture corpus through a **single code-native tool,
`proxy_brain`**. Instead of a fixed menu of narrow commands, `proxy_brain` runs a
block of the agent's own Python inside the Kali sandbox, with a pre-imported SDK
called `redamon` as its only door to the traffic. Anything an interactive web proxy does, the
agent scripts here: Repeater, Intruder, Comparer, Sequencer, Decoder, JWT Editor,
Autorize, Turbo Intruder, all composed in a few lines over the captured history. A
vulnerability is usually an *algorithm* (an oracle queried in a loop, a value
extracted bit by bit, a chain where each step depends on the last), which code
expresses and a fixed vocabulary cannot.

This **replaces the ten former `proxy_*` tools** (`proxy_search`, `proxy_get`,
`proxy_sitemap`, `proxy_params`, `proxy_grep`, `proxy_diff`, `proxy_to_curl`,
`proxy_query`, `proxy_replay`, `proxy_fuzz`). Everything those tools did is now one
line of `redamon.*`, and the agent can chain them with loops, conditionals, math
and crypto to build real exploit oracles. The MCP tool
(`proxy_brain`, [`mcp/servers/network_recon_server.py`](../../mcp/servers/network_recon_server.py))
pre-imports the SDK, runs the code, and returns its `print(...)` output; the SDK is
[`mcp/servers/redamon.py`](../../mcp/servers/redamon.py). Every response the SDK
hands back is attacker-controlled, so the tool output is wrapped as untrusted before
it reaches the LLM.

### The mechanism explained simply

Before the detailed subsections below, here is the whole thing in plain words. The
sections that follow re-tell the same story with the exact endpoints, line numbers
and enforcement code.

**The one idea.** `proxy_brain` lets the agent write a little Python program and run
it, with a ready-made toolbox called `redamon` already imported. That toolbox is not
a database client and holds no real credential: it is a thin phone line back to the
trusted agent. The agent is the only side that knows *who* the traffic belongs to and
is the only side allowed to say *where* a live request may go. The sandbox does the
risky work but cannot choose the target or the tenant. That split is the entire
security design.

#### Which container runs the SDK, and who it talks to

The SDK runs inside **`redamon-kali`** (the kali sandbox), the least-trusted box,
because that is where attacker-facing traffic and LLM-written code execute. From
there it talks to two other containers: the **`redamon-agent`** for every decision
and every piece of data, and the **`redamon-capture-proxy`** whenever it actually
sends live traffic to a target.

```mermaid
flowchart LR
    subgraph kali["redamon-kali (kali-sandbox) — least trusted"]
      PB["proxy_brain tool<br/>runs the agent's Python"] --> RS["redamon SDK<br/>(pre-imported)"]
    end
    subgraph agentc["redamon-agent — trusted brain"]
      EP["/traffic/exec · /traffic/replay · /traffic/browser"]
      SEC["holds INTERNAL_API_KEY<br/>+ DATABASE_URL"]
    end
    CP["redamon-capture-proxy<br/>egress guard + re-capture"]
    TGT["target host"]
    RS -->|"HTTP: signed ctx tag + SCANNER_API_KEY header"| EP
    EP -->|"data / curl recipe / allow-or-deny"| RS
    RS -->|"live curl routed via -x proxy"| CP --> TGT
    TGT -->|response| CP --> RS
```

The kali box is given only the **scoped** `SCANNER_API_KEY` (transport auth: "I am an
allowed caller") and the agent's URL. It is deliberately **not** given
`INTERNAL_API_KEY` or any database URL, so a foothold there cannot forge a tenant or
read the store directly.

#### Two hops: the agent triggers, then the code calls back

The confusing part is that the agent triggers the tool, yet it is *kali* that sends
the request in the diagrams. The reason is that there are **two separate hops**, and
the code runs in kali, not in the agent.

- **Hop 1 (agent -> kali):** the agent invokes the `proxy_brain` MCP tool, handing it
  the Python code and a freshly minted `REDAMON_CTX` tag. This is the trigger. The
  agent now steps back and waits.
- **Hop 2 (kali -> agent):** kali is now *executing that code*. Every time a line like
  `redamon.replay(...)` runs, the SDK needs something it does not have locally, so it
  opens a **new** request back to the agent, using the tag as its ID badge.

Think of the agent as a manager who hands a worker a sealed task sheet and an ID
badge, then leaves. The worker goes to a separate room and, whenever it needs a file,
walks to the archive window and asks, showing the badge. The manager is not standing
there fetching files; the worker asks, and the clerk checks the badge first.

```mermaid
sequenceDiagram
    participant A as redamon-agent (brain)
    participant K as redamon-kali (SDK runs here)
    participant T as target
    A->>K: HOP 1 — run this Python + your REDAMON_CTX tag
    Note over K: the code executes INSIDE kali
    K->>A: HOP 2 — redamon.search(...)  {op, args, ctx}
    A-->>K: tenant-scoped rows (agent did the query)
    K->>A: HOP 2 — redamon.replay(...) {op, id, mutate, ctx}
    A-->>K: host-pinned curl_args + signed replay tag
    K->>T: kali runs the curl (through the capture proxy)
    T-->>K: the real response (the agent never sees it)
    K-->>A: printed output = the tool result
```

Hops 3 to 5 (the middle rows) can repeat many times inside a single run, because the
code loops. Each repeat is kali initiating, because the code lives in kali.

#### The key twist: the agent hands out permits, it does not fetch

For **read** operations the agent does the work itself (the corpus lives on its side)
and returns the answer. But for **live** operations the agent **never contacts the
target**. It returns *instructions*:

- **`/traffic/replay` and `/traffic/fuzz`** reply with a ready-to-run, **host-pinned**
  `curl_args` string plus a signed lineage tag. Kali then runs that curl itself,
  through the capture proxy, and the target's response comes back **to kali**, not
  through the agent.
- **`/traffic/browser`** replies with the host to pin to and an allow-or-deny for each
  step. The real Chromium runs in kali, through the capture proxy.

So the agent is a **broker that issues permits**, not a proxy that fetches things. It
keeps the trust (identity, host-pinning, phase and budget checks) but stays off the
traffic path, while kali does the sending but can only run the exact permit it was
handed. That is what stops a compromised sandbox from becoming an SSRF pivot or a
cross-tenant leak.

| Operation | What the agent returns | Who contacts the target |
|---|---|---|
| read (`search`, `get`, `grep`, `diff`, `query`, …) | the actual data | nobody |
| active (`replay`, `fuzz`, `batch`) | a host-pinned `curl_args` + signed tag | **kali**, via the capture proxy |
| browser (`goto`, `click`, `eval`, …) | pin info + per-step allow/deny | **kali's** Chromium, via the capture proxy |

#### The auth tag: how `REDAMON_CTX` is made and checked

Identity travels as a small **signed JSON token** — the same idea as a JWT, but
home-rolled in pure stdlib ([`redamon_ctx.py`](../../agentic/redamon_ctx.py)). The
agent mints it fresh on every `proxy_brain` call and the `/traffic/*` endpoint
verifies it. The token is **not secret** (anyone can base64-decode the claims); it is
**tamper-proof** (nobody without `INTERNAL_API_KEY` can forge or alter it).

```mermaid
flowchart TD
    subgraph mint["MINT — agent side, per proxy_brain call (_build_redamon_ctx)"]
      C1["gather claims from TRUSTED ContextVars:<br/>source=agent, user_id, project_id, session, phase, tool"]
      C2["canonical JSON<br/>(whitelisted fields, sorted keys, compact)"]
      C3["HMAC-SHA256 over the bytes, keyed with INTERNAL_API_KEY"]
      C4["token = b64url(claims) + '.' + b64url(sig)"]
      C1 --> C2 --> C3 --> C4
    end
    C4 -->|"injected as REDAMON_CTX on the CHILD process only"| K["kali runs the code"]
    K -->|"every /traffic/* call carries the tag verbatim"| V1
    subgraph verify["VERIFY — agent side, on each call (_verify_traffic_ctx)"]
      V1["read 'source' only to PICK the key<br/>(agent -> INTERNAL_API_KEY, recon -> SCANNER_API_KEY)"]
      V2["recompute HMAC, constant-time compare"]
      V3["re-canonicalize claims == original bytes?"]
      V1 --> V2 --> V3
      V3 -->|"no · missing key · key=changeme · no tenant"| F["401 — fail closed"]
      V3 -->|yes| OK["bind tenant from the SIGNED claims<br/>(never from the request body)"]
    end
```

Practically, the mint is four steps: **gather claims -> canonical JSON -> HMAC-SHA256
with the agent's private key -> base64url both halves and join with a dot.** Two
things make it safe:

1. The claims come from the agent's own request context, **never from the code the LLM
   wrote**, so the sandbox cannot name a different tenant.
2. The signing key never leaves the agent. Kali carries the finished token but cannot
   read past it or produce a new one, and the endpoint re-derives the tenant from the
   *verified* claims and hard-injects it into every SQL `WHERE`.

### The broker pattern (why kali never touches the database)

`proxy_brain` runs in the **least-trusted** container (the Kali sandbox, which talks
to targets) and holds **no database credential**. It reaches the corpus only through
two authenticated endpoints on the trusted agent, mirroring how the graph terminal
reaches Neo4j (`redagraph` -> `/graph/exec`): the worker that could be compromised by
a target never has a direct line to the store.

```mermaid
flowchart LR
    subgraph kali["kali sandbox (UNTRUSTED, no DB cred, no signing key)"]
      CODE["proxy_brain<br/>(agent's Python)"] --> SDK["redamon SDK"]
    end
    subgraph agent["agent (TRUSTED, holds INTERNAL_API_KEY + DATABASE_URL)"]
      EXEC["/traffic/exec<br/>read, tenant-scoped"]
      RPLY["/traffic/replay<br/>PREPARE: host-pinned, phase-gated, budgeted"]
    end
    PG[("captured_http_transactions")]
    PROXY["capture proxy<br/>(egress guard + re-capture)"]
    SDK -- "read ops" --> EXEC --> PG
    SDK -- "active ops (PREPARE)" --> RPLY -- "curl_args + signed replay tag" --> SDK
    SDK -- "worker runs curl" --> PROXY --> PG
```

- **Read ops** (`search`, `get`, `sitemap`, `params`, `grep`, `diff`, `to_curl`,
  `query`) POST to `/traffic/exec`
  ([`api.py:2980`](../../agentic/api.py#L2980)), which dispatches to the same
  tenant-scoped `traffic_tools` logic the old read tools used and returns the
  formatted text.
- **Active ops** (`replay`, `batch`, `fuzz`) POST to `/traffic/replay`
  ([`api.py:3022`](../../agentic/api.py#L3022)), which is a **PREPARE**: it reads the
  origin (tenant-scoped), builds the host-pinned curl, signs a replay lineage tag,
  and returns `curl_args` + `ctx`. The SDK's `_run` then executes the curl **from
  inside kali, through the capture proxy** ([`redamon.py:329`](../../mcp/servers/redamon.py#L329)),
  so the send is egress-guarded and re-captured exactly like `execute_curl`.
- **Browser ops** (`redamon.browser(id)` and its `.goto` / `.click` / `.eval` / … )
  POST to `/traffic/browser` ([`api.py:3122`](../../agentic/api.py#L3122)), a **PREPARE**
  that verifies the tag, gates the exploitation phase, re-reads the origin
  (tenant-scoped) to pin the navigation host/port/scheme, and enforces a per-session
  **action budget** (every action, including `open`, costs one unit). A real Chromium
  then runs **inside kali, through the capture proxy** (routed by `browser_launch.py`),
  so every request it makes is egress-guarded and re-captured as
  `tool=proxy_brain_browser`. The SDK caps concurrent browsers at 3.

### Tenant isolation (the signed tag)

The kali worker presents the scoped `SCANNER_API_KEY` for transport auth but does
**not** hold `INTERNAL_API_KEY`, so it cannot forge a tenant claim. Identity travels
as an HMAC-signed tag the agent mints and the endpoint verifies:

```mermaid
flowchart TD
    REQ["SDK call from kali<br/>(carries the signed ctx tag)"] --> VER["_verify_traffic_ctx<br/>HMAC-verify vs INTERNAL_API_KEY"]
    VER -->|"no key / key=changeme<br/>bad or missing tag"| BAIL["401 (fail closed)"]
    VER -->|"valid: user_id + project_id"| APPLY["_apply_traffic_tenant<br/>bind tenant into request-local ContextVars"]
    APPLY --> SQL["every WHERE hard-injects<br/>project_id = %(p)s AND user_id = %(u)s<br/>as bound params"]
    SQL --> QB{"query op only:<br/>columns/aggs/ops/order<br/>validated vs frozensets"}
    QB -->|invalid| REJ["reject"]
    QB -->|valid| RUN["execute; forced scope<br/>prepended before any code-supplied where"]
```

Four properties stop a compromised sandbox or an attacker-controlled body from
reaching another tenant's traffic:

1. **Tenant comes from a signed tag, never from the code.** `_verify_traffic_ctx`
   ([`api.py:2944`](../../agentic/api.py#L2944)) HMAC-verifies the tag against
   `INTERNAL_API_KEY` and **fails closed** if the key is absent or `changeme`, or if
   the tag lacks a `user_id` / `project_id`. The agent code the LLM writes cannot
   supply or override the tenant.
2. **Every SQL WHERE hard-injects `project_id = %(p)s AND user_id = %(u)s`** as bound
   parameters, across all read ops (the active op's `fetch_transaction` origin read
   is scoped the same way, so an agent cannot replay another tenant's request).
3. **The `query` op never accepts raw SQL.** It is a constrained query *builder*: the
   code picks columns, aggregations, operators, group-by and order-by from
   allowlisted frozensets, and the forced tenant scope is prepended before any
   code-supplied condition. There is no SQL-string escape surface, so no `pg_sleep` /
   `dblink` / DDL / UNION is expressible.
4. **Request-local ContextVars.** `_apply_traffic_tenant`
   ([`api.py:2965`](../../agentic/api.py#L2965)) binds the verified tenant into
   ContextVars per FastAPI request task, so concurrent requests never leak scope.

### The `redamon` SDK surface

**Read ops** (no traffic, tenant-scoped, any phase):

| Call | What it returns |
|---|---|
| `redamon.search(filters)` | HTTP history rows (`.id`, `.method`, `.status`, `.url`, `.host`, `.path`); summaries only, never bodies. Filters: host, method, status, statusClass, tool, source, session, run, hasAuth, reflected, only5xx, `q`, `bodyq`, limit. |
| `redamon.get(id, part)` | Full request or response (headers + body) for one transaction (`request` / `response` / `both`); the way to pull a body into scope. |
| `redamon.sitemap()` | Distinct endpoints observed, with hit counts and statuses. |
| `redamon.params()` | Distinct request parameters + an injectability guess (seq-id / uuid / jwt / base64). |
| `redamon.grep(pattern)` | Substring search across response bodies, with a snippet. |
| `redamon.diff(a, b)` | Structural diff of two responses (status / length / headers / body). |
| `redamon.to_curl(id)` | A captured request rendered as a reproducible curl (for the report). |
| `redamon.query(spec)` | Constrained analytical query builder over allowlisted columns / aggregations (no raw SQL). |

**Decode / crypto** (pure, no traffic): `redamon.decode(v)` peels
base64 / url / hex / gzip layers; `redamon.jwt(tok)` parses a JWT and forges variants
(`.forge(alg_none=True | secret=".." | claims={..})`).

**Active ops** (live traffic, exploitation phases only):

| Call | What it does |
|---|---|
| `redamon.replay(id, mutate)` | Resend a captured request with fields changed (`method`, `path`, `query`, `param`, `headers`, `dropHeaders`, `cookie`, `body`). **Host / scheme / port pinned to the origin.** Returns a `Response` (`.status`, `.headers`, `.body`, `.length`). |
| `redamon.batch(id, muts, parallel=True)` | One replay per mutation; `parallel=True` fires them **concurrently** (a real race-condition window: limit overrun, double-spend, coupon reuse). |
| `redamon.fuzz(id, insertion_point, payloads)` | An automated payload sweep over one query parameter; one `Response` per payload. |

**Browser ops** (live traffic, exploitation phases only — the rendered-DOM oracle
for bugs that only surface after JavaScript runs, e.g. DOM-based XSS, SPA-only routes,
JS-minted CSRF):

| Call | What it does |
|---|---|
| `redamon.browser(id)` | Open a real Chromium **pinned to txn `id`'s host / port / scheme**; find the id with `search` first. Costs one action. |
| `.goto(path)` `.click(sel)` `.fill(sel, v)` `.submit(sel)` `.press(sel, key)` `.eval(js)` | **Budgeted** actions; an off-origin navigation is refused and a redirect that crosses off the origin aborts the run. |
| `.dom()` `.text(sel)` `.html(sel)` `.console()` `.alerts()` `.url()` | **Free** reads (no budget). `.alerts()` returns any fired `alert/confirm/prompt` — the in-band DOM-XSS oracle. |
| `.close()` | Tear the browser down; at most 3 open at once. |

**Result:** `redamon.finding(kind, txn_id, evidence, severity)` records a finding;
`redamon.manual(section=None)` returns the on-demand cookbook (core map, or one of
twenty-one technique sections — including `browser`) so the recipes never bloat the prompt.

### How an active send actually runs (host pin + budget)

```mermaid
flowchart TD
    SDK["redamon.replay/batch/fuzz(id, ...)"] --> PREP["POST /traffic/replay (PREPARE)"]
    PREP --> PHASE{"tag phase in<br/>exploitation / post_exploitation?"}
    PHASE -->|no| B403["403 (fail closed)"]
    PHASE -->|yes| ORI["fetch_transaction(id)<br/>TENANT-SCOPED read of the origin"]
    ORI -->|not owned| B404["404 not found (or not in your project)"]
    ORI -->|owned| BUILD["build curl: method/path/query/params/<br/>headers/cookie/body MUTABLE<br/>host/scheme/port PINNED to origin"]
    BUILD --> BUD{"session send budget<br/>used + N <= budget?"}
    BUD -->|no| B429["429 budget exhausted"]
    BUD -->|yes| TAG["sign replay tag (source=agent, is_replay, origin_id)<br/>return curl_args + ctx"]
    TAG --> RUN["SDK _run: worker sends curl<br/>through the capture proxy"]
    RUN --> ROW["proxy egress-guards + re-captures:<br/>new row isReplay=true, originId=origin"]
```

Four safety properties, all enforced in code on the agent side (kali cannot bypass
them by editing its own script):

1. **Host is pinned to the origin (scope safety).** `mutate` can change the method,
   path, query, params, headers, cookie and body, but the host / scheme / port always
   come from the origin transaction, and `_origin_url`
   ([`traffic_tools.py:537`](../../agentic/traffic_tools.py#L537)) forces a rooted path
   and asserts the rebuilt URL's netloc equals the origin's, raising `ValueError`
   otherwise (the F1 host-pin hardening). A replay can never be aimed at a different
   host, so it is neither a scope-bypass nor an SSRF primitive; the endpoint turns
   that `ValueError` into a `400 replay refused`.
2. **Per-send phase gate.** `/traffic/replay` reads the phase from the verified tag
   and returns `403` unless it is `exploitation` or `post_exploitation`
   ([`api.py:3036`](../../agentic/api.py#L3036)). Reads and decode work in any phase;
   only sends are gated.
3. **Per-session send budget.** One confirmed `proxy_brain` run can fan out to many
   sends, so `_TRAFFIC_REPLAY_SENDS` counts prepared sends per session and refuses
   over `TRAFFIC_REPLAY_BUDGET` (default 1000) with a `429`
   ([`api.py:3082`](../../agentic/api.py#L3082)). A runaway loop cannot flood a target.
4. **Replays go back through the capture proxy.** The worker sends via the same curl
   path, so each is egress-guarded again *and* re-captured with a verified
   `is_replay` / `origin_id` lineage tag minted from `INTERNAL_API_KEY`. Replayed
   traffic is first-class captured traffic, not a side channel.

### Phase, danger, and stealth gating

- **Danger:** `proxy_brain` is in `DANGEROUS_TOOLS`
  ([`project_settings.py`](../../agentic/project_settings.py)) and flagged with a
  warning glyph in the ToolMatrix UI, so it prompts for confirmation before it runs.
  The host-pin, phase gate and budget bound what that one confirmation can do.
- **Phase map** (`TOOL_PHASE_MAP` in
  [`project_settings.py`](../../agentic/project_settings.py)): `proxy_brain` is
  enabled in all three phases so the agent can *read and analyse* in any phase, but the
  `/traffic/replay` endpoint gates *sending* to the exploitation phases (above).
- **Stealth mode** ([`stealth_rules.py`](../../agentic/prompts/stealth_rules.py)):
  fuzz / batch / rapid replay are held back; read and decode stay free.

### How it fits an engagement

```mermaid
flowchart LR
    RECON["recon + agent tools<br/>generate traffic"] --> CORPUS[("captured_http_transactions")]
    CORPUS --> BRAIN["proxy_brain<br/>(writes Python over the redamon SDK)"]
    BRAIN -- "read: search/sitemap/params/grep/diff/get/query" --> BRAIN
    BRAIN -- "crypto: decode / jwt().forge()" --> BRAIN
    BRAIN -- "active: replay / batch / fuzz" --> CORPUS
    BRAIN --> FIND["redamon.finding(...)"]
```

A typical flow lives in one code block: map the surface with `sitemap` / `params`,
find leads with `search` / `grep`, confirm a specific behaviour with `get` / `diff`
or an ad-hoc `query`, build the oracle in Python (a regex over `.body`, a `.status`
or `.length` flip, a timing delta), then `replay` / `batch` / `fuzz` to actively
confirm, and record it with `finding`. The active sends feed straight back into the
corpus as `isReplay` rows, so the agent's own attack traffic is searchable and
auditable. The agent reads the relevant `redamon.manual("<technique>")` section right
before it writes that code.

### Result bounding

Output is bounded to keep the corpus from flooding the context window: search
summaries cap at `_MAX_ROWS`, bodies truncate at `_MAX_BODY_CHARS`, `diff` caps its
unified-diff hunks, offloaded bodies return an explicit "not available agent-side"
marker rather than a failure, and only what the agent `print(...)`s returns to the
LLM.

---

## See also

- Full design rationale and phase plan: [`internal/mitmproxy_integration_plan.md`](../../_local/internal/mitmproxy_integration_plan.md)
- Threat model context: [`internal/stride/README.TM.STRIDE.md`](../../_local/internal/stride/README.TM.STRIDE.md)
- Proxy image and addon: [`scanners/capture_proxy/`](../../scanners/capture_proxy/)
- Agent tools: [`agentic/traffic_tools.py`](../../agentic/traffic_tools.py)

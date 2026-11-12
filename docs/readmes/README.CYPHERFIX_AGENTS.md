# CypherFix Agents — Vulnerability Triage & Automated Code Remediation

## Overview

**CypherFix** is RedAmon's automated vulnerability remediation pipeline. It bridges the gap between discovering vulnerabilities (via reconnaissance, DAST scanning, and AI-powered pentesting) and actually fixing them in code. The pipeline consists of two independent AI agents that operate in sequence:

1. **Triage Agent** - Scores every finding in the Neo4j attack surface graph
   with a fixed risk model, groups the findings that share a fix, has an LLM
   check the evidence behind the ones it can judge, and writes one remediation
   per group. The score model is deterministic and runs with no LLM at all; see
   [Score model v3](#score-model-v3).
2. **CodeFix Agent** — Takes a single remediation entry, clones the target repository, explores the codebase, implements the fix using a ReAct loop, and opens a pull request.

Both agents run inside the existing `agent` container and communicate with the frontend via dedicated WebSocket connections.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [End-to-End Workflow](#end-to-end-workflow)
3. [Triage Agent](#triage-agent)
   - [File Structure](#triage-file-structure)
   - [The run steps](#the-run-steps-and-why-only-the-publish-writes)
   - [Collection](#collection)
   - [Persistence](#persistence)
   - [Tools](#triage-tools)
   - [Score model v3](#score-model-v3)
   - [Grouping, review and remediation](#grouping-review-and-remediation)
   - [The run protocol](#the-run-protocol)
   - [State Model](#triage-state-model)
   - [WebSocket Protocol](#triage-websocket-protocol)
4. [CodeFix Agent](#codefix-agent)
   - [File Structure](#codefix-file-structure)
   - [ReAct Loop Architecture](#react-loop-architecture)
   - [Orchestrator Workflow](#orchestrator-workflow)
   - [Tool System](#codefix-tool-system)
   - [Diff Block & Approval Flow](#diff-block--approval-flow)
   - [GitHub Integration](#github-integration)
   - [State Model](#codefix-state-model)
   - [WebSocket Protocol](#codefix-websocket-protocol)
5. [LLM Provider Routing](#llm-provider-routing)
6. [Frontend Integration](#frontend-integration)
7. [Configuration Reference](#configuration-reference)
8. [Container & Runtime Environment](#container--runtime-environment)

---

## Architecture Overview

```mermaid
flowchart TB
    subgraph Frontend["Frontend (Next.js Webapp)"]
        CF_TAB[CypherFixTab]
        TRIAGE_PROG[TriageProgress]
        REM_DASH[RemediationDashboard]
        REM_DETAIL[RemediationDetail]
        DIFF_VIEW[DiffViewer + ActivityLog]
        HOOKS[useCypherFixTriageWS\nuseCypherFixCodeFixWS]
    end

    subgraph Backend["Backend (FastAPI — agent container)"]
        WS_TRIAGE["/ws/cypherfix-triage"]
        WS_CODEFIX["/ws/cypherfix-codefix"]
        REST_API["REST API\n/api/remediations"]
    end

    subgraph TriageAgent["Triage Agent"]
        T_ORCH[TriageOrchestrator]
        T_FACTS["Fact sets + one row per finding"]
        T_SCORE["score_model v3 (no LLM)"]
        T_GROUP["Deterministic group keys"]
        T_REVIEW["Evidence review (no tools bound)"]
    end

    subgraph CodeFixAgent["CodeFix Agent"]
        C_ORCH[CodeFixOrchestrator]
        C_LOOP[ReAct While-Loop]
        C_TOOLS["11 Code Tools\ngithub_read, github_edit,\ngithub_grep, github_bash, ..."]
        C_GIT[GitHubRepoManager\nclone → branch → commit → PR]
    end

    subgraph Data["Data Layer"]
        NEO4J[(Neo4j Graph DB)]
        GITHUB[(GitHub Repository)]
        WEBAPP_DB[(PostgreSQL\nRemediations)]
    end

    CF_TAB --> HOOKS
    HOOKS <-->|WebSocket JSON| WS_TRIAGE
    HOOKS <-->|WebSocket JSON| WS_CODEFIX

    WS_TRIAGE --> T_ORCH
    T_ORCH --> T_CYPHER
    T_ORCH --> T_LLM
    T_LLM --> T_TOOLS
    T_CYPHER --> NEO4J
    T_TOOLS --> NEO4J
    T_ORCH -->|POST /api/remediations/batch| WEBAPP_DB

    WS_CODEFIX --> C_ORCH
    C_ORCH --> C_LOOP
    C_LOOP --> C_TOOLS
    C_LOOP --> C_GIT
    C_GIT --> GITHUB
    C_ORCH -->|PUT /api/remediations/:id| WEBAPP_DB

    REM_DASH -->|GET /api/remediations| REST_API
    REST_API --> WEBAPP_DB
```

---

## End-to-End Workflow

```mermaid
sequenceDiagram
    participant User
    participant Frontend
    participant TriageAgent
    participant Neo4j
    participant LLM
    participant CodeFixAgent
    participant GitHub

    Note over User,GitHub: Phase 1 - Triage
    User->>Frontend: Confirm the triage dialog (preflight numbers)
    Frontend->>TriageAgent: WS: start_triage
    TriageAgent->>Frontend: POST /api/internal/triage-runs (authorize)
    TriageAgent->>Neo4j: Project fact sets, then one row per finding
    Neo4j-->>TriageAgent: Facts and findings
    Note over TriageAgent: Score (no LLM), then group by fix
    TriageAgent->>LLM: Review the evidence behind reviewable findings
    LLM-->>TriageAgent: Factor corrections, each with a quote
    Note over TriageAgent: Verify every quote, recompute tier and score
    TriageAgent->>LLM: Write the fix-item prose, per group
    TriageAgent->>Frontend: POST .../publish (claim the write)
    TriageAgent->>Neo4j: Publish the ranking, guarded by updated_at
    TriageAgent->>Frontend: POST .../remediations (upsert by group key)
    TriageAgent->>Frontend: POST .../finish
    TriageAgent->>Frontend: WS: triage_complete

    Note over User,GitHub: Phase 2 — Review
    User->>Frontend: Browse remediations table
    User->>Frontend: Select remediation → view details

    Note over User,GitHub: Phase 3 — CodeFix
    User->>Frontend: Click "Start CodeFix"
    Frontend->>CodeFixAgent: WS: start_fix {remediation_id}
    CodeFixAgent->>GitHub: Clone repo, create branch
    loop ReAct Loop (max 100 iterations)
        CodeFixAgent->>LLM: System prompt + conversation
        LLM-->>CodeFixAgent: Reasoning + tool calls
        CodeFixAgent->>CodeFixAgent: Execute tools (read, search, edit)
        CodeFixAgent->>Frontend: WS: diff_block (for each edit)
        alt Approval Required
            Frontend->>User: Show diff for review
            User->>Frontend: Accept / Reject
            Frontend->>CodeFixAgent: WS: block_decision
        end
    end
    CodeFixAgent->>GitHub: Commit, push, create PR
    CodeFixAgent->>Frontend: WS: pr_created + codefix_complete
```

---

## Triage Agent

### Triage File Structure

```
agentic/cypherfix_triage/
├── __init__.py
├── orchestrator.py            # score, read layers, group, review, combine, remediate, publish
├── score_model.py             # The risk model and combine_layers(): the ONLY producer of a final score. Pure
├── layers.py                  # Stored properties <-> BaseLayer / ReviewLayer / DecisionLayer. Pure
├── finding_ops.py             # One finding's evidence, and an external (MCP) review's eligibility
├── fact_queries.py            # Project fact sets + one row per finding
├── grouping.py                # Deterministic group keys (one problem, one fix)
├── evidence.py                # The bundle: normalised, secret-redacted, capped; its hash is what a review is valid for
├── remediation.py             # Fix-item fields, every one computed in code
├── intel.py                   # KEV / EPSS / PoC via the vulnx MCP tool
├── run_client.py              # authorize, heartbeat, publish, finish
├── state.py                   # RemediationDraft, TriageState
├── tools.py                   # The Neo4j read path. No LLM tools are bound
├── project_settings.py        # Load CypherFix settings from webapp API
├── websocket_handler.py       # WebSocket endpoint + the run registry
└── prompts/
    ├── __init__.py
    ├── review.py              # the evidence-review prompt AND its output validation
    └── remediation_prose.py   # the only thing a model writes about a fix item
```

### The run steps, and why only the publish writes

```mermaid
flowchart LR
    subgraph Mem["In memory: nothing is written"]
        direction TB
        A["A. Score: fact sets + one row per finding = the BASE layer, no LLM"]
        L["Read stored reviews and decisions; adopt unchanged v3.1 reviews"]
        B["B. Group: deterministic keys, no LLM"]
        C["C. Review: only findings with no still-valid review; every quote verified"]
        X["Combine: combine_layers(base, review, decision); groups re-scored"]
        D["D. Remediate: fields in code, prose by LLM, text from builtin reviews only"]
        A --> L --> B --> C --> X --> D
    end

    R["R. Authorize, before reading anything"] --> Mem
    Mem --> E["E. Publish: claim, then write"]
    NEO4J[(Neo4j)] --> A
    E --> NEO4J
    E --> DB[(PostgreSQL)]
```

**Steps A to D happen entirely in memory; Step E is the only thing a run
writes.** (A person's verdict and an external agent's review write one finding
each, outside any run, and a publish that follows reads them rather than
overwriting them.) That single property is what makes a run safe to stop, safe to refuse
and safe to run beside a scan: until the publish is claimed, the previous
ranking is still what an operator sees, and a run that is killed halfway has
changed nothing at all.

It also gives the design its failure posture:

- the run authorises BEFORE it reads, so a run that will not be allowed to
  publish does not first spend minutes and LLM budget discovering that;
- a publish that is refused writes nothing, rather than part of a result;
- the LLM being unreachable costs detail, never the ranking: a finding keeps
  whatever review it had, and one with none publishes as "Not reviewed" with its
  maths intact;
- a Stop is refused once the run is publishing, and the publish and the fix-list
  save run under `asyncio.shield`, so a cancel never splits them;
- a batch the driver cannot land after its retries is counted in
  `publish_failed`, and the run finishes `completed_partial`.

**The three layers.** BASE is written only by a publish; REVIEW by a run (the
built-in AI, `triage_ai_channel = 'builtin'`) or by `write_review` for an external
agent (`'mcp'`); DECISION only by `set_human_verdict`. A review is valid while its
`triage_ai_evidence_hash` equals the finding's `triage_evidence_hash`. A run never
reviews over a valid `mcp` review, and re-reviews its own only after a model or
prompt change. The final values (`triage_priority_score`, `triage_tier`,
`triage_state`, `triage_factors`, `triage_decided_by`, `triage_disposition`,
`triage_blocker`) come from `combine_layers` and nothing else.

**Disposition (plan 10).** `Final.disposition` answers "can this go in a
report?" (`reportable` | `candidate` | `info` | `excluded`) and `Final.blocker`
says what a candidate lacks. `combine_layers` computes them LAST, with
`score_model.disposition_of`, from the other final values and the four gate
facts the run stored in `triage_tier_inputs.gates` (`gate_facts`: reachable now,
attributed, controlled, impactful, each true / false / null). So:

- a resolved state or a person's False positive is `excluded`; proof or a
  person's Real is `reportable`; no impact or a key public by design is `info`;
- a review reaches the answer only through the `false_positive` state it can
  set, which yields a `candidate` blocked by "AI review: likely false positive",
  never `excluded`;
- otherwise the blocker is the first gate that is false, then the first that is
  null (`unknown: <gate>`), then the tier rule. The gates move no score.

The rules and their words are the webapp's read-side ones
(`webapp/src/lib/triage/disposition.ts`), which every reader falls back to for
a node no v3.10 run has rescored; `agentic/tests/test_disposition_parity.py`
runs the Python half over the webapp's vector files. A base stored before the
gates (no `gates` key) yields `None` for both, so a verdict on such a node
leaves the readers computing the answer until the next run.

### Collection


Nine hardcoded Cypher queries run against Neo4j to collect the full attack surface:

The collection queries live in `cypherfix_triage/fact_queries.py` and come in
two kinds.

**Project fact sets**, read once per run: which hosts are live, which ports an
active scan found, which packages are actually served, what the agent proved,
which hosts appear in threat intelligence, which assets are sensitive, and what
the run skipped (a tripped breaker). The `skipped_hosts` query returns the
coverage record's keys whole, and `build_project_facts` splits them: a
`host:port` or `[v6]:port` key goes to `ProjectFacts.skipped_ports` and leaves
only the findings on that host and port "unknown: reachable now"; a bare host
key, or one whose port does not parse, goes to `skipped_hosts` and covers the
whole host. A finding's port is its `target_port`, else the port its host
spelling names, a URL's scheme default included, as `circuit_breaker.host_key`
keys it; a finding on the host itself, with no port, is covered only by a bare
host key (`score_model._skipped`, since `SCORE_MODEL_VERSION` v3.12.0).

**One row per finding**, per label, using `COUNT {}` / `EXISTS {}` subqueries
rather than `OPTIONAL MATCH` chains. That shape is the point: the old queries
chained OPTIONAL MATCH, so a GVM finding hanging off three Technologies plus a
Port plus a Subdomain came back five times, each scoring differently, and
whichever row Neo4j returned last won. One OSV advisory hangs off up to eleven
packages in the dev graph. Verified on a real graph: 536 findings, no duplicate
ids.

The join happens in Python, in `score_model.score(finding, facts, intel)`, which
is pure.

All queries are tenant-filtered with `$userId` and `$projectId`. They also
hand-write their own `NOT n:Muted` term: they run through `run_static_query`,
which deliberately does not go through `scope_query`, so the exclusion every
agent query gets for free is absent here.

### Persistence

Findings are published through `publish_triage_layers`, one managed transaction
(`execute_write`, retried on deadlocks) per batch of 500. Each batch locks its
nodes, re-reads their current review, decision and live proof, skips a node whose
`updated_at` moved since the run read it, and calls the orchestrator's `combine`
with the node as it is NOW, so a decision or an external review written mid-run
wins. It never writes a decision, `updated_at` or `:Muted`, and skips muted nodes.
A person's verdict (`set_human_verdict`) and an MCP review (`write_review`)
rescore their finding in their own managed transaction, locked before read, with
a 15-second timeout that surfaces as `busy`. Remediations are upserted by
`(projectId, groupKey)` in ONE transaction through
`POST /api/internal/triage-runs/[runId]/remediations`.

The old path deleted every pending remediation and then created the new ones,
outside a transaction: a failure in between left the project with no fix list at
all, and a row the CodeFix agent was working on could be deleted underneath it,
taking its branch and its PR link with it. Anything a person or CodeFix has
touched is now never rewritten.

### Triage Tools

**The triage agent binds NO tools.** It used to have `query_graph` and
`web_search`, which meant a model steered by scanner output could write its own
Cypher and its own search queries. Both are gone: Steps A to D read the graph
through the fixed queries in `cypherfix_triage/fact_queries.py`, and the review
and prose calls bind nothing at all, so an injected instruction has nothing to
reach for.

The one outbound call triage can make is `cve_intel` on the kali-sandbox MCP
server, checked against a one-name allowlist. Only CVE ids leave the machine,
regex-validated in code, and only numbers and booleans are kept from the reply.

### Score model v3

The weighted-sum algorithm is gone. It added points per signal, which counted
one fact several times (severity, CVSS score and CVSS vector all describe the
same thing), summed signals that mean the same thing (KEV + EPSS + a public
PoC), and ADDED impact to likelihood when risk is impact TIMES likelihood.

`cypherfix_triage/score_model.py` is a pure module with no I/O. For every open
finding it estimates four probabilities and multiplies them:

| Factor | Meaning | Source |
|---|---|---|
| **C** | P(the finding is real) | How it was detected: an exploit that ran, a matcher with captured proof, a QoD band, a version guess |
| **L** | P(exploited \| real) | The MAXIMUM of the exploit signals, never a sum, then capped modifiers |
| **I** | Impact | The CVSS impact sub-score, else the numeric score, else severity, else the class table |
| **R** | Reachability | A live endpoint, an actively-scanned port, a served package, a login wall, a local-only vector |

```
risk  = min(1, C x L x I x R)
tier  = T1 Act now | T2 Act soon | T3 Plan | T4 Track     (fixed rules)
score = 25 x tier_level + 25 x risk                        (0 to 100)
```

The tier is INSIDE the score, so one sort key gives "tier first, then risk" and
the tier bands meet rather than overlap.

**State is decided before the score.** A `fixed`, `gone` or `inactive` finding
leaves the ranking entirely rather than being demoted to a small number that
still sorts above something real. `gone` needs evidence of absence: the
`gone_hosts` fact reads `RESOLVES_TO` from each label's own end (Subdomain ->
IP, so an IP is gone only when no Subdomain resolves to it) and leaves out every
host with any key on an org `Domain`'s `recon_skipped_hosts`, port stripped as
`circuit_breaker.hostname_of` strips it for the prune: a host the run did not
re-check, even on one port, is unknown, not gone.

**Agent proof has a confidence floor.** A `ChainFinding` proves the finding it
`CONFIRMS` only when `coalesce(toInteger(cf.confidence), 80) >= 70`
(`PROOF_MIN_AGENT_CONFIDENCE`, `AGENT_CONFIDENCE_DEFAULT`, `agent_proof_counts`
in `score_model.py`). The missing-value default is the writer's own
(`chain_graph_writer.fire_record_finding`), so stored proof is unchanged. The
same numbers sit in three places that must agree: the `proof` fact query (and
its reducer, which feeds `is_proven`), `triage_mixin._LIVE_PROOF`, and the
`proof_types` the detail read lists; `tests/test_fix_triage_proof_mirror.py`
pins the mixin's copies to the model's.

**A finding is classed by type before source.** `origin_discovery` and
`security_check` MERGE the same `waf_bypass` node and `source` is set on create
only, so any finding whose `type` names a `SECURITY_CHECK_CLASSES` entry goes to
`classify_security_check` whatever its source.

Three decisions worth knowing, because each was a live defect:

- **Unknown is not info.** OSV writes `severity: info` to mean "never graded"
  (all 419 PYSEC advisories in the dev graph), so ungraded maps to 0.45, not
  0.02. This is the one place a "higher" severity word scores lower.
- **A blanket severity cannot raise a class.** The GitHub hunt stamps "high" on
  all 284 of its secrets, 119 of which are private IP addresses, so for writers
  like that the class table caps I.
- **Nothing without impact leaves Track unless it is proven**, so a famous KEV
  CVE whose own vector says `C:N/I:N/A:N` cannot be Act now.

Every table is data, so calibration is a diff of numbers rather than of code,
and `SCORE_MODEL_VERSION` changes with them. All eight guarantees of the design
are tests in `agentic/tests/test_score_model.py`; monotonicity, the missing-data
rule and group risk are checked over seeded random cases.

**C is the one factor that learns.** Every Real / False positive click is a
label for the DETECTOR that produced the finding (`detector_key`: a nuclei
template, a GVM OID, a TruffleHog detector; advisories key on the source, since
a verdict on one CVE says nothing about another). C then becomes a Beta
posterior over this user's own verdicts, with the rule-based C as its prior:

```
C = (10 x C_rule + real) / (10 + real + fp)        bounded to [0.1, 0.99]
```

Ten pseudo-counts is deliberately slow: a detector is judged on a handful of
findings at first, and three unlucky clicks must not switch a real one off. The
counts come from `detector_labels`, the only fact query scoped to `$userId`
rather than to a project, because a detector that is noise on one of your
projects is noise on the next. It is never scoped wider than one user. Proven
findings are exempt, the same rule the review obeys. With no labels stored the
rule stands unchanged, which is why the v3.1.0 ranking is byte-identical to
v3.0.0 on a graph nobody has clicked. Tests:
`agentic/tests/test_triage_detector_learning.py`.

### Grouping, review and remediation

- **Group** (`cypherfix_triage/grouping.py`): deterministic keys, no LLM. The
  same CVE from two scanners is one group; every advisory on one package is one
  group; a secret's key is a hash of its value, never the value. The `secrets`
  fact query returns `s.matched_text` for that, and names the detector by the
  pattern (`coalesce(s.secret_type, s.key_type)`): js_recon's `key_type` is only
  the pattern's category. The `vulnerabilities` query projects the fields the
  scanner-specific keys read, so web cache poisoning groups by technique and
  unkeyed header or parameter (`cache:<technique>:<vector>`), subdomain takeover
  by provider and method (`takeover:<provider>:<method>`), GraphQL by check type
  (`graphql:<vulnerability_type>`) and AI findings by OWASP LLM class and
  payload class (`ai:<owasp>:<payload>`). A node that stores none of those
  fields (an older or imported one) is its own group, never one key for the
  whole source. When a run produces a group key no `Remediation` row
  carries, the fix-list route re-points the orphaned row that shares at least
  half of the group's findings (largest overlap, then protected, then newest;
  once per run) instead of creating a duplicate, and reports it as `repointed`.
- **Review** (`cypherfix_triage/evidence.py`, `cypherfix_triage/prompts/review.py`): the LLM
  corrects FACTORS against quoted evidence and never produces a score. Every
  quote is verified as a substring of what was sent; an unverifiable correction
  becomes "no change". `security_check` and OSV findings never reach it. A
  Secret's bundle carries `Value (redacted)` and `Context (redacted)`: the
  context has the matched value masked by name before the shape redaction and
  the short cap, so a secret of no known shape never reaches the model. Rule 3
  of the prompt lists a login page, a redirect to login, a 401/403 auth wall and
  the page the server returns for a random path as false-positive shapes
  (`REVIEW_PROMPT_VERSION` `review-v3`). A review that answers `false_positive`
  moves the finding to the board's false-positive section but never out of the
  client report, Insights or the MCP analytics counts: only a person's
  `likely_noise` (with `triage_source = 'human'`) or a resolved state does that
  (`webapp/src/lib/triage/reportable.ts`). The reviewer reads target-controlled
  text, so an injected sentence can re-rank a finding, never hide it.
- **Remediate** (`cypherfix_triage/remediation.py`): every field that decides
  anything is computed in code. `targetRepo` comes from project settings and
  never from model output, because it decides where CodeFix pushes.

### The run protocol

A run is a `TriageRun` row, so activation, version save, the delta preview,
import and delete can see one. Four calls, all fail-closed:

| Call | What it does |
|---|---|
| `POST /api/internal/triage-runs` | Authorise, BEFORE reading anything. Strict ownership, ignoring `ACCESS_ENFORCE` |
| `.../heartbeat` | Every 30s. The reply carries `abort`; two failures in a row are treated as one |
| `.../publish` | A conditional `running -> publishing` transition. A run that lost its claim writes nothing |
| `.../finish` | Always, from a `finally`. A run left `running` blocks activation until its heartbeat expires |

Steps A to D are entirely in memory; Step E is the only thing that writes
findings, in batches of 500, each row guarded by the `updated_at` it was read at,
so a finding a scan re-ingested mid-run is skipped and picked up next time. The
heartbeat keeps a `publishing` run alive (and records its phase and progress),
and `finish` updates the status only from `running` or `publishing`: a run
already marked lost stays lost and is audited `triage.finish.late`.

**Beside Mute Rules.** A triage run and an "apply to current graph" of
[Mute Rules](../../redamon.wiki/Mute-Rules.md) are both tracked graph writers.
The triage dialog's preflight (`/api/triage/preflight`) refuses to start a run
while an apply is running, as it does for every live writer except a scan, and
an apply refuses to start while a triage run is `running` or `publishing`. The
run's own authorise call checks only for a version activation and for another
triage run.

A verdict is also a Mute Rules **guard**. A rule never mutes a finding with
`triage_source = 'human'`, `triage_status = 'confirmed'` or a `triage_proof`, and
a rule mute already on one is released by the next apply, or by the next scan
that finds it again. The collection queries and the publish skip muted findings,
but `set_human_verdict` matches them, so a person's confirmation on a finding a
rule muted releases it the same way. The exception is a verdict over MCP:
`set_human_verdict(refuse_muted=True)` refuses a muted finding, because from an
access token that release would be an unmute. A **Reset** removes
`triage_source`, and with it the guard: a reset finding may be rule-muted, and
pruned like any stale finding.
The rule's mute write re-checks the guards, so a verdict set between the
sweep's read and its write is never hidden.

### Triage State Model

```mermaid
erDiagram
    TriageState {
        string user_id
        string project_id
        string session_id
        dict settings
        dict raw_data "Output from 9 Cypher queries"
        RemediationDraft analysis_result
        string status "initializing|collecting|analyzing|saving|complete|error"
        string current_phase
        string error
    }

    TriageFinding {
        string title
        string description
        string severity "critical|high|medium|low|info"
        int priority "0 = highest"
        string category "sqli|xss|rce|exposure|secret|..."
        string remediation_type "code_fix|dependency_update|config_change|..."
        list affected_assets
        float cvss_score
        list cve_ids
        list cwe_ids
        list capec_ids
        string evidence
        bool exploit_available
        bool cisa_kev
        string solution
        string fix_complexity "low|medium|high|critical"
    }

    RemediationDraft {
        list findings
        string summary
        dict by_severity
        dict by_type
    }

    TriageState ||--o| RemediationDraft : analysis_result
    RemediationDraft ||--o{ TriageFinding : findings
```

### Triage WebSocket Protocol

**Endpoint:** `/ws/cypherfix-triage`

**Incoming messages:**

| Type | Payload | Description |
|------|---------|-------------|
| `init` | `{user_id, project_id, session_id?}` | Initialize session |
| `start_triage` | — | Launch triage pipeline |
| `stop` | — | Cancel running triage |
| `ping` | — | Keepalive |

**Outgoing messages:**

| Type | Payload | Description |
|------|---------|-------------|
| `connected` | `{session_id}` | Session initialized |
| `triage_phase` | `{phase, description, progress}` | Phase update with 0–100 progress |
| `thinking` | `{thought}` | LLM reasoning text |
| `thinking_chunk` | `{chunk}` | Streaming reasoning chunk |
| `tool_start` | `{tool_name, tool_args}` | Tool execution started |
| `tool_complete` | `{tool_name, success, output_summary}` | Tool execution finished |
| `triage_complete` | `{total_remediations, by_severity, by_type, summary}` | Pipeline complete |
| `error` | `{message, recoverable}` | Error occurred |
| `stopped` | — | Triage cancelled |
| `pong` | — | Keepalive response |

`stop` while the run is publishing is refused (`{stopped: false, reason:
"publishing"}`): the publish finishes, then the run ends normally.

**Headless start and stop (MCP).** `POST /triage/runs` and
`POST /triage/runs/stop` (webapp-internal, `X-Internal-Key`) start and stop the
same run through `start_detached_run`, with no socket attached. The webapp calls
them for MCP `start_triage_run` / `stop_triage_run` after its own checks (scope,
ownership, preflight, the 30-minute cooldown and the 12-runs-per-day cap). The
run records `trigger: "mcp"` and the token id, so the board and
`get_triage_status` show who started it. A browser that opens the dialog while a
headless run is live attaches to it rather than starting another.

---

## CodeFix Agent

### CodeFix File Structure

```
agentic/cypherfix_codefix/
├── __init__.py
├── orchestrator.py            # Pure ReAct while-loop (Claude Code pattern)
├── state.py                   # DiffBlock, CodeFixSettings, CodeFixState
├── project_settings.py        # Load CypherFix settings from webapp API
├── websocket_handler.py       # WebSocket endpoint + CodeFixStreamingCallback
├── prompts/
│   ├── __init__.py
│   ├── system.py              # Dynamic system prompt with remediation context
│   └── diff_format.py         # Instructions for structured diff output
└── tools/
    ├── __init__.py            # CODEFIX_TOOLS schema definitions (11 tools)
    ├── github_repo.py         # GitHubRepoManager: clone, branch, commit, push, PR
    ├── glob_tool.py           # File pattern matching (pathlib)
    ├── grep_tool.py           # Content search (ripgrep wrapper)
    ├── read_tool.py           # File reading with line numbers
    ├── edit_tool.py           # Exact string replacement + diff block generation
    ├── write_tool.py          # File creation/overwrite
    ├── bash_tool.py           # Shell execution with safety checks
    ├── list_dir_tool.py       # Directory listing
    ├── symbols_tool.py        # Tree-sitter AST symbol extraction
    ├── find_definition_tool.py # Symbol definition lookup
    ├── find_references_tool.py # Symbol usage finder
    └── repo_map_tool.py       # PageRank-scored codebase overview
```

### ReAct Loop Architecture

The CodeFix agent replicates **Claude Code's exact agentic design**: a pure ReAct loop where the LLM is the sole controller. There is no hardcoded state machine deciding tool order — the LLM decides which tools to use, when to retry, and when to stop. The orchestrator is simply a **while loop** that calls the LLM, executes its tool requests, feeds results back, and repeats.

```mermaid
flowchart TB
    START([Start]) --> INIT[Load settings + remediation]
    INIT --> CLONE[Clone repo + create branch]
    CLONE --> EXPLORE[List directory structure]
    EXPLORE --> BUILD[Build system prompt with\nvulnerability context]

    BUILD --> LOOP_START{ReAct Loop\niteration < max}

    LOOP_START -->|Yes| GUIDANCE{Pending\nguidance?}
    GUIDANCE -->|Yes| INJECT[Inject user message]
    GUIDANCE -->|No| LLM_CALL
    INJECT --> LLM_CALL[Call LLM]

    LLM_CALL --> THINKING[Stream reasoning to frontend]
    THINKING --> CHECK{Tool calls\nin response?}

    CHECK -->|No| FINALIZE

    CHECK -->|Yes| EXEC_TOOLS[Execute tools\nparallel: read, search\nsequential: edit, write, bash]

    EXEC_TOOLS --> EDIT_CHECK{Edit tool?\nApproval required?}
    EDIT_CHECK -->|Yes| DIFF[Generate DiffBlock\nStream to frontend]
    DIFF --> WAIT[Wait for user decision\n5 min timeout]
    WAIT --> DECISION{Accept?}
    DECISION -->|Yes| NEXT_TOOL[Continue]
    DECISION -->|No| REJECT[Inject rejection reason\ninto conversation]
    REJECT --> NEXT_TOOL
    EDIT_CHECK -->|No| NEXT_TOOL

    NEXT_TOOL --> LOOP_START

    LOOP_START -->|No: max reached| FINALIZE

    FINALIZE{Files\nmodified?}
    FINALIZE -->|Yes| COMMIT[Commit + push + create PR]
    COMMIT --> COMPLETE([codefix_complete\nstatus: pr_created])
    FINALIZE -->|No| NO_FIX([codefix_complete\nstatus: no_fix])
```

### Orchestrator Workflow

The `CodeFixOrchestrator.run()` method executes these phases:

| Phase | Action | Details |
|-------|--------|---------|
| 1. Settings | `load_cypherfix_settings()` | Fetch project config from webapp API |
| 2. Remediation | `GET /api/remediations/:id` | Load vulnerability details (title, CVEs, solution, evidence) |
| 3. Status Update | `PUT /api/remediations/:id` | Set `status: "in_progress"`, clear previous `agentNotes` |
| 4. Clone | `GitHubRepoManager.clone()` | Shallow clone (`--depth 50`), create fix branch `cypherfix/{remediation_id}` |
| 5. Explore | `github_list_dir()` | Get repo structure for system prompt |
| 6. Init LLM | `_init_llm()` | Create LangChain client based on model provider |
| 7. System Prompt | `build_codefix_system_prompt()` | Inject vulnerability details + repo structure + tool rules |
| 8. ReAct Loop | While loop (max 100 iterations) | LLM reasons → tools execute → results feed back |
| 9. Finalize | Commit → Push → PR (or no_fix) | Update remediation status in database |

### CodeFix Tool System

The agent has 11 tools available, mirroring Claude Code's tool set:

```mermaid
flowchart LR
    subgraph Search["Search & Navigate"]
        GLOB[github_glob\nFile pattern matching]
        GREP[github_grep\nContent search - ripgrep]
        LISTDIR[github_list_dir\nDirectory listing]
        SYMBOLS[github_symbols\nAST symbol extraction]
        FINDDEF[github_find_definition\nSymbol definition lookup]
        FINDREF[github_find_references\nUsage finder]
        REPOMAP[github_repo_map\nPageRank codebase overview]
    end

    subgraph ReadWrite["Read & Write"]
        READ[github_read\nFile reading with line numbers]
        EDIT[github_edit\nExact string replacement\n+ diff block generation]
        WRITE[github_write\nFile creation/overwrite]
    end

    subgraph Execute["Execute (isolated sandbox)"]
        BASH[github_bash\nShell commands\nrun via docker exec in\nephemeral secret-free sandbox]
    end
```

#### Tool Details

| Tool | Purpose | Key Behavior |
|------|---------|-------------|
| `github_glob` | Find files by glob pattern | Returns paths sorted by modification time, max 500 results |
| `github_grep` | Search file contents (regex) | Wraps `rg`, supports `files_with_matches`, `content`, `count` modes |
| `github_read` | Read file with line numbers | cat -n format, tracks files in `state.files_read` for edit pre-check |
| `github_edit` | Exact string replacement | Generates `DiffBlock`, streams to frontend, triggers approval flow |
| `github_write` | Create or overwrite file | Creates parent directories, adds to `state.files_modified` |
| `github_bash` | Shell command execution | **Runs in an isolated per-job sandbox container** (secret-free, network-isolated, `cap_drop=ALL`, read-only rootfs), driven via `docker exec` through the webapp→orchestrator path — never in the agent. 600s timeout. The old in-agent shell + 4-pattern blocklist is removed (closes T6/E10) |
| `github_list_dir` | List directory contents | Type indicators (file/dir) |
| `github_symbols` | Tree-sitter AST symbols | Supports 15 languages, extracts functions/classes/methods with line ranges |
| `github_find_definition` | Find symbol definitions | AST-based, skips node_modules/vendor/__pycache__ |
| `github_find_references` | Find symbol usages | AST-based, skips definition nodes and comments |
| `github_repo_map` | Ranked codebase overview | PageRank scoring by cross-reference count, respects token budget |

**Execution strategy:**
- **Parallel**: Search and read tools run concurrently via `asyncio.gather()`
- **Sequential**: Edit, write, and bash tools run one at a time (edit triggers approval check)

### Build Sandbox Isolation (threats T6 / E10)

A cloned repo is **untrusted external input** (malicious `postinstall` scripts, prompt-injected build instructions). Of the 11 tools, only `github_bash` *executes* repo content — so its execution is moved out of the agent container (which holds `INTERNAL_API_KEY`, Neo4j/Postgres creds, every per-user LLM key, and the GitHub token) into a dedicated sandbox.

```mermaid
flowchart LR
    AGENT["agent\nLLM control loop\n(holds secrets)"] -->|"github_bash(cmd)"| WEBAPP["webapp\nX-Internal-Key"]
    WEBAPP -->|"X-Orchestrator-Key"| ORCH["recon-orchestrator\n(real docker socket)"]
    ORCH -->|"docker exec"| SBX["codefix-sandbox\nephemeral · secret-free\ncap_drop=ALL · no-new-privileges\nread-only rootfs · codefix-net"]
    AGENT -. "clone / edit / commit / push\n(token stays here)" .-> WORK[("shared work dir\nrepo rw · .git ro")]
    SBX --- WORK
```

Key properties:

- **Per-job, ephemeral.** A `redamon-codefix-<job>` container is spawned at the start of a run and destroyed on completion / disconnect / TTL (a reaper cleans orphans).
- **No secrets.** The sandbox environment is empty — a full RCE during a build finds nothing to steal.
- **No internal reach.** It sits on an isolated `codefix-net` bridge with NAT egress (so `npm`/`pip` installs work) but **no RedAmon peer** — it cannot reach webapp/Neo4j/Postgres/agent.
- **Hardened runtime.** `cap_drop=ALL`, `security_opt=no-new-privileges`, read-only rootfs (writable tmpfs + worktree only), non-root user, CPU/memory/PID limits.
- **Command channel is the docker control plane**, not a shared network: the agent cannot reach the orchestrator directly, so requests flow `agent → webapp (X-Internal-Key) → orchestrator (X-Orchestrator-Key) → docker exec`. This preserves the rule that only the webapp holds the orchestrator key.
- **Token isolation.** Clone/commit/push run on the agent side with the token via `GIT_ASKPASS`; the sandbox mounts the worktree (`.git` read-only) and never sees the token.

If the sandbox image (`redamon-codefix-sandbox:latest`, built via `docker compose --profile tools build`) is missing, `github_bash` is cleanly disabled (file edits still work) — it never falls back to in-agent execution.

### Diff Block & Approval Flow

When `github_edit` executes successfully, it generates a `DiffBlock`:

```mermaid
sequenceDiagram
    participant LLM
    participant Orchestrator
    participant EditTool
    participant Frontend
    participant User

    LLM->>Orchestrator: tool_use: github_edit(file, old, new)
    Orchestrator->>EditTool: Execute replacement
    EditTool->>EditTool: Verify old_string exists & is unique
    EditTool->>EditTool: Replace text in file
    EditTool->>EditTool: Generate DiffBlock with context
    EditTool->>Frontend: WS: diff_block {block_id, file_path, old_code, new_code, ...}

    alt require_approval = true
        EditTool->>Orchestrator: Set pending_approval = true
        Orchestrator->>Orchestrator: await approval_future (5 min timeout)
        Frontend->>User: Show diff with Accept/Reject buttons
        User->>Frontend: Decision
        Frontend->>Orchestrator: WS: block_decision {block_id, decision, reason?}
        alt Accepted
            Orchestrator->>Orchestrator: Continue loop
        else Rejected
            Orchestrator->>Orchestrator: Inject rejection reason into messages
            Note over LLM: LLM sees rejection and adjusts approach
        end
    end
```

**DiffBlock fields:**

| Field | Type | Description |
|-------|------|-------------|
| `block_id` | string | Unique ID (`block-{8-hex}`) |
| `file_path` | string | Relative path from repo root |
| `language` | string | Detected from extension (python, javascript, typescript, java, go, ...) |
| `old_code` | string | Original code being replaced |
| `new_code` | string | Replacement code |
| `context_before` | string | 3 lines before the change |
| `context_after` | string | 3 lines after the change |
| `start_line` | int | 1-indexed line number where change starts |
| `end_line` | int | 1-indexed line number where change ends |
| `status` | string | `pending` → `accepted` or `rejected` |

### GitHub Integration

The `GitHubRepoManager` handles all Git and GitHub operations:

All git invocations run with hooks disabled (`-c core.hooksPath=/dev/null`) so a malicious cloned repo cannot plant a hook that fires on commit/push.

```mermaid
flowchart LR
    CLONE["clone()\n--depth 50\ntoken via GIT_ASKPASS\n(not in URL)"] --> BRANCH["create_branch()\ncypherfix/{rem_id}"]
    BRANCH --> EDIT["Agent edits files\nvia github_edit"]
    EDIT --> COMMIT["commit()\nstages ONLY approved files\nauthor: CypherFix"]
    COMMIT --> PUSH["push()\n--force origin\nbranch allow-list"]
    PUSH --> PR["create_pr()\nPyGithub API\n422 → update existing"]
```

| Operation | Details |
|-----------|---------|
| **Clone** | Shallow clone to the shared work dir `{CODEFIX_WORK_BASE}/{job}/repo` (the build sandbox mounts this; `.git` mounted read-only). Token supplied via `GIT_ASKPASS` — **never in the clone URL or `.git/config`**. Removes existing dir, 120s timeout |
| **Branch** | `git checkout -b cypherfix/{remediation_id}` |
| **Commit** | Author: `CypherFix <cypherfix@redamon.io>`. **Stages only the LLM's approved files (`state.files_modified`) — never `git add -A`**, so build artifacts or files a malicious build slipped into the worktree cannot reach the PR |
| **Push** | Force-push (allows re-runs on same branch). **Branch allow-list**: refused if the target is the default branch / `main` / `master`, or does not match the configured fix-branch prefix (closes T7). Token sanitized from errors |
| **PR** | Creates via GitHub API; if 422 (already exists), finds and updates existing PR |

### CodeFix State Model

```mermaid
erDiagram
    CodeFixState {
        string remediation_id
        string remediation_title
        string user_id
        string project_id
        string session_id
        Path repo_path "Path to cloned repo"
        string branch_name "e.g. cypherfix/abc123"
        string base_branch "e.g. main"
        set files_read "Files read by agent"
        set files_modified "Files changed by agent"
        bool pending_approval
        string pending_block_id
        int iteration "Current ReAct iteration"
        string status "initializing|in_progress|completed|error"
    }

    CodeFixSettings {
        string github_token
        string github_repo "owner/repo"
        string default_branch "main"
        string branch_prefix "cypherfix/"
        bool require_approval "true"
        string model "LLM model identifier"
        int max_iterations "100"
        int tool_output_max_chars "20000"
        int model_context_window "200000"
    }

    DiffBlock {
        string block_id "block-{8-hex}"
        string file_path
        string language
        string old_code
        string new_code
        string context_before
        string context_after
        int start_line
        int end_line
        string description
        string status "pending|accepted|rejected"
    }

    CodeFixState ||--|| CodeFixSettings : settings
    CodeFixState ||--o{ DiffBlock : diff_blocks
```

### CodeFix WebSocket Protocol

**Endpoint:** `/ws/cypherfix-codefix`

**Incoming messages:**

| Type | Payload | Description |
|------|---------|-------------|
| `init` | `{user_id, project_id, session_id?}` | Initialize session |
| `start_fix` | `{remediation_id}` | Launch CodeFix for a specific remediation |
| `block_decision` | `{block_id, decision, reason?}` | Accept or reject a diff block |
| `guidance` | `{message}` | Inject user guidance into next ReAct iteration |
| `stop` | — | Cancel running fix |
| `ping` | — | Keepalive |

**Outgoing messages:**

| Type | Payload | Description |
|------|---------|-------------|
| `connected` | `{session_id}` | Session initialized |
| `codefix_phase` | `{phase, description}` | Phase update (cloning_repo, exploring_codebase, implementing_fix, awaiting_approval) |
| `thinking` | `{thought}` | Full LLM reasoning (up to 20K chars) |
| `thinking_chunk` | `{chunk}` | Streaming reasoning chunk |
| `tool_start` | `{tool_name, tool_args}` | Tool execution started (args truncated to 200 chars) |
| `tool_complete` | `{tool_name, success, output_summary}` | Tool finished (summary truncated to 500 chars) |
| `diff_block` | `{block_id, file_path, language, old_code, new_code, ...}` | Code change for user review |
| `block_status` | `{block_id, status}` | Block accepted or rejected |
| `fix_plan` | `{plan}` | Overall fix plan from LLM |
| `pr_created` | `{pr_url, pr_number, branch, title, files_changed, additions, deletions}` | PR opened on GitHub |
| `codefix_complete` | `{remediation_id, status, pr_url?}` | Workflow complete (pr_created, no_fix, or error) |
| `error` | `{message, recoverable}` | Error occurred |
| `stopped` | — | Fix cancelled |
| `pong` | — | Keepalive response |

---

## LLM Provider Routing

Both agents share the same multi-provider routing logic:

```mermaid
flowchart LR
    MODEL["Model identifier"] --> CHECK{Prefix?}
    CHECK -->|"openai_compat/"| OC[ChatOpenAI\ncustom base_url]
    CHECK -->|"openrouter/"| OR[ChatOpenAI\nOpenRouter endpoint]
    CHECK -->|"bedrock/"| BR[ChatBedrockConverse\nAWS credentials]
    CHECK -->|"claude-*"| AN[ChatAnthropic]
    CHECK -->|default| OAI[ChatOpenAI]
```

| Prefix | Provider | Required Env Var |
|--------|----------|------------------|
| `openai_compat/` | Custom OpenAI-compatible server | `OPENAI_COMPAT_BASE_URL`, `OPENAI_COMPAT_API_KEY` |
| `openrouter/` | OpenRouter | `OPENROUTER_API_KEY` |
| `bedrock/` | AWS Bedrock | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` |
| `claude-*` | Anthropic | `ANTHROPIC_API_KEY` |
| _(default)_ | OpenAI | `OPENAI_API_KEY` |

Both agents use `temperature=0` for deterministic output. Triage uses `max_tokens=16384`, CodeFix uses `max_tokens=8192`.

---

## Frontend Integration

### Component Tree

```
CypherFixTab
├── EmptyState                         # No remediations yet — "Start Triage" prompt
├── TriageProgress                     # Live triage progress bar + phase indicator
├── RemediationDashboard               # Table of all remediations
│   ├── RemediationFilters             # Severity/status/type filters
│   ├── SeverityBadge                  # Color-coded severity tag
│   ├── StatusBadge                    # Status indicator (pending, in_progress, pr_created, ...)
│   └── RemediationTypeIcon            # Icon for code_fix, dependency_update, etc.
├── RemediationDetail                  # Single remediation detail view
│   ├── EvidenceSection                # Evidence display
│   ├── SolutionSection                # AI-suggested solution
│   └── CodeFixButton                  # "Start CodeFix Agent" trigger
└── DiffViewer                         # CodeFix live activity view
    ├── ActivityLog                    # Chronological log of all agent events
    ├── DiffBlock                      # Individual code diff with syntax highlighting
    │   ├── FileHeader                 # File path + language badge
    │   └── DiffLine                   # Single diff line (addition/deletion/context)
    └── BlockActions                   # Accept/Reject buttons
```

### WebSocket Hooks

| Hook | Endpoint | Purpose |
|------|----------|---------|
| `useCypherFixTriageWS` | `/ws/cypherfix-triage` | Manages triage session, progress tracking |
| `useCypherFixCodeFixWS` | `/ws/cypherfix-codefix` | Manages codefix session, activity log, diff blocks, approval flow |

### Standalone Page

`/cypherfix` — A dedicated page (`webapp/src/app/cypherfix/page.tsx`) that provides a standalone remediations dashboard outside the graph view, accessible from the global header.

---

## Configuration Reference

CypherFix settings are stored per-project in the PostgreSQL `Project` model and loaded at runtime:

| Setting | DB Field | Default | Used By |
|---------|----------|---------|---------|
| GitHub Token | `cypherfixGithubToken` | — | CodeFix (repo operations) |
| Default Repository | `cypherfixDefaultRepo` | — | CodeFix (clone target) |
| Default Branch | `cypherfixDefaultBranch` | `main` | CodeFix (base branch) |
| Branch Prefix | `cypherfixBranchPrefix` | `cypherfix/` | CodeFix (fix branch naming) |
| Require Approval | `cypherfixRequireApproval` | `true` | CodeFix (user must approve each edit) |
| LLM Model | `cypherfixLlmModel` | — | Both agents (fallback: `agentOpenaiModel`) |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBAPP_API_URL` | `http://webapp:3000` | Webapp API base URL |
| `CYPHERFIX_REPOS_BASE` | `/tmp/cypherfix-repos` | Base directory for cloned repos |
| `NEO4J_URI` | `bolt://neo4j:7687` | Neo4j connection (triage) |
| `NEO4J_USER` | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` | `redamon_neo4j` | Neo4j password |
| `TAVILY_API_KEY` | — | Tavily web search API key (triage) |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `ANTHROPIC_API_KEY` | — | Anthropic API key |
| `OPENROUTER_API_KEY` | — | OpenRouter API key |
| `OPENAI_COMPAT_BASE_URL` | — | Custom OpenAI-compatible endpoint |
| `OPENAI_COMPAT_API_KEY` | — | Custom OpenAI-compatible API key |
| `AWS_ACCESS_KEY_ID` | — | AWS credentials for Bedrock |
| `AWS_SECRET_ACCESS_KEY` | — | AWS credentials for Bedrock |

---

## Container & Runtime Environment

Both agents run inside the existing `agent` Docker container. The container ships with a full set of language runtimes so the CodeFix agent can build, test, and lint any target repository:

| Runtime | Version | Commands |
|---------|---------|----------|
| **Node.js** | 20 LTS | `node`, `npm`, `npx`, `yarn`, `pnpm` |
| **Python** | 3.11 | `python3`, `pip` |
| **Go** | 1.22 | `go build`, `go test`, `go mod` |
| **Ruby** | 3.3 | `ruby`, `gem`, `bundler` |
| **Java** | OpenJDK 21 | `java`, `javac`, `mvn` |
| **PHP** | 8.4 | `php`, `composer` |
| **.NET** | SDK 8.0 | `dotnet build`, `dotnet test` |
| **Build tools** | — | `make`, `gcc`, `g++` |
| **Utilities** | — | `git`, `ripgrep (rg)`, `jq`, `curl`, `wget`, `unzip`, `file`, `ssh` |

### Docker Compose

```yaml
agent:
  volumes:
    - ./agentic:/app                          # Source code (live mount)
    - cypherfix-repos:/tmp/cypherfix-repos    # Cloned repos for CodeFix
```

The `cypherfix-repos` named volume provides persistent storage for cloned repositories during CodeFix runs. Repos are cleaned up after each session.

### System Prompt

The CodeFix system prompt is dynamically built per-remediation and includes:
- Agent identity and ReAct behavior rules
- Available runtimes and tools
- Vulnerability details (title, severity, CVEs, affected assets, evidence, solution)
- Repository structure (from `github_list_dir`)
- Tool usage rules (read before edit, uniqueness checks, indentation preservation)
- Security guidelines (parameterized queries, output encoding, allow-lists)

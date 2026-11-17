# Tradecraft 2.0 end-to-end matrix

The live validation of phase 10 of the Tradecraft 2.0 plan: guinea-pig labs as targets, a
library ingested from the default presets as the knowledge, and the agent attacking each
lab with the library on (arm A), off (arm B, the control) and in "Search only" (arm A-search),
plus six single checks of the rules and the layer-1 checks of the library itself. It is a
live run the owner starts by hand: it needs the stack, the internet once (the library build)
and a real model, so it is never part of the unit gate.

| File | What it holds |
|---|---|
| `scenarios.yaml` | The labs, arms, single checks, layer-1 questions, the budget and the pass rules |
| `runner.py` | The command line, the preflight, the chat and Agent in the Loop drivers, the trace reader, the matrix loop |
| `lanes.py` | The runs, the scheduler (longest expected first, the 40-minute cap, the 4:20 budget guard, one owner mode at a time) and the lanes' addresses and ports |
| `labs.py` | One Compose project per run (`tc-e2e-<run>-<suffix>`) and the generated overrides of the older labs |
| `oracles.py` | Each lab instance's own secret and the oracle that reads it back |
| `checks.py` | The trace parsers (the agent's result formats) and the checks of every arm and single check |
| `report.py` | The pass rules, `report.md` and the per-run JSON files, and the redactor |
| `library.py`, `library.yaml` | The library build, snapshot and restore (T10.2, S15) |

Standard library only, host Python 3. Unit tests (no stack):
`docker run --rm -v "$PWD:/repo" -w /repo -e PYTHONPATH=/repo --entrypoint python redamon-agent:latest -m pytest tests/test_tradecraft_matrix_runner.py tests/test_tradecraft_matrix_library.py`.

## Run it

```bash
python3 tooling/scripts/tradecraft_e2e/runner.py --dry-run                 # the plan; starts nothing
flock "<PLAN>/run/heavy.lock" python3 tooling/scripts/tradecraft_e2e/runner.py --lanes 7 --model <model id>
python3 tooling/scripts/tradecraft_e2e/runner.py --only L3-A-1 --only L4-A-1 --lanes 2 --model <model id>   # the pilot
```

`--model` is required for a run: the agent model of every run's project, one the e2e owner's
provider serves. `--only` takes a run id (`L3-A-1`), a lab (`L3`: its arm runs and the single
checks on it), an arm (`A`, `B`, `A_search`, `single`), a lab and arm (`L3-A`) or a single check
(`S4`); it skips the layer-1 checks, unless one of its values is `layer1` (`--only layer1` runs
them alone, to re-run that gate). `--no-build`, `--no-restore` and `--no-layer1` skip those
steps. `--agent-logs` names the agent's session-log folder; by default it is the source of the
agent container's `/app/logs` mount (the checkout the stack runs from), and the preflight stops
when that folder holds no session log.
The report goes to `_local/tradecraft-e2e/runs/<date>/report.md`, one JSON file per run beside
it (the trace the checks read); nothing under `_local/` is committed.

**Before the first run (MC-9, MC-10):** the library is built and snapshotted (`library.py`,
T10.2); the e2e owner and ops accounts each have a model provider (add one acting as them:
the runner never copies a key), or the install offers them one (an instance provider); the RBAC sharing and permissions switches, Agent in the Loop
and the MCP server are on for S2, S3 and S4 (a check whose switch is off in `.env` is reported
"skipped: switch off"; any other refusal while setting a check up, such as a share refused by
policy or a refused step-up password, fails it with its reason); the host can hold `--lanes`
lab instances and agent sessions.

## The library (`library.py`, `library.yaml`)

Every agent run reads the same library: the e2e owner's nine resources, added from the
default presets through the product's own routes, frozen in a snapshot that the preflight
restores before each matrix run. Stored resources answer from their copy, so only the CVE
archive (Live) needs the internet during a run.

| Resource | Type | Storage and settings |
|---|---|---|
| `hacktricks` | MkDocs wiki | Live (the card pass) |
| `payloadsallthethings` | GitHub repository | Stored from the archive; focus Tag only |
| `claude-bughunter` | GitHub repository | Stored; Focused on SQL injection and SSRF × payloads and bypasses, Balanced; the focus preview runs first |
| `web-hacking-techniques-index` | Website | Stored; Auto (its sitemap) |
| `hexbrain-payloads` | Website | Stored; Auto; `/payloads/*`, inside the folder |
| `web-hacking-techniques-archive-github` | GitHub repository | Live (the same archive twice) |
| `trickest-cve` | CVE archive | Live; the path pattern Check URL finds |
| `mitmproxy-docs` | Sphinx docs | Live |
| `ired-team` | GitBook | Live, with the fake login `cookie=fake-session` (S2, S3) |

```bash
python3 tooling/scripts/tradecraft_e2e/library.py plan --model <id>    # what build would send; starts nothing
python3 tooling/scripts/tradecraft_e2e/library.py models               # the model ids the e2e owner may pick
flock "<PLAN>/run/heavy.lock" python3 tooling/scripts/tradecraft_e2e/library.py build --model <id>
python3 tooling/scripts/tradecraft_e2e/library.py snapshot
python3 tooling/scripts/tradecraft_e2e/library.py restore              # the preflight runs it
python3 tooling/scripts/tradecraft_e2e/library.py status               # the stamp; warns when ingestion changed
```

`build` (about 1.5-2.5 h, the internet and the model: MC-9) signs in as the e2e owner and
stops with exit 4 when the account has no model provider (a person adds one acting as it;
nothing copies a key). It sets the librarian model and the search settings of
`scenarios.yaml`'s `owner_search`, then per resource runs Check URL, the focus preview where
`library.yaml` asks, and Add, keeps two add jobs in flight (the agent runs two at a time),
and judges each report: the job, the type, the map size, the storage, the stored pages, the
readiness line, the login and the focus. It resumes: a resource already built is judged
again, one whose job failed is deleted and added again, one not in `library.yaml` is
deleted. The record, counts only, goes to `_local/tradecraft-e2e/library-build.json`.

`snapshot` and `restore` act on one library only, the e2e owner's (`tc-e2e-owner@e2e.local`):
no option names another account, and restore refuses a snapshot of any other. `snapshot`
refuses while the owner has a running job. In one read-only transaction it copies the
owner's rows of every tradecraft table but the jobs, the live generation only, with no claim
(`active_job_id` empty), no GitHub token and no site login (cookies, headers and basic auth
are left out), into `_local/tradecraft-e2e/library/` (private files), with `stamp.json`: the
plan commit, a hash of `agentic/tradecraft/ingest/`, the columns, row counts and checksums.
It replaces only a folder it made (its stamp and its files, nothing else), so a wrong
`--dir` is refused with nothing removed; a failed snapshot leaves the previous one in place.
`restore` checks every file against the stamp first, then in one transaction deletes the
owner's tradecraft rows (a running job refuses it), copies the files back, writes the card's
fake login (`cookie=fake-session`) back on the S2/S3 resource, moves the rows to the owner's
id of today when the account was made again, leaves out the choices of projects that are
gone, moves the four autoincrement sequences past the restored ids, and checks that the
search trigger filled every row. Any error rolls the whole restore back.
The preflight warns when the ingestion code changed since the stamp: build the library
again then.

`--pg-container`, `--pg-user`, `--pg-db` and `--dir` point `snapshot` and `restore` at a test
copy: a session's database on the plan's disposable Postgres
(`tooling/scripts/tradecraft_pg_testdb.sh`) and a snapshot folder of its own. They never
change whose library is read or replaced: the e2e owner's only. The seed of the e2e
accounts (`runner.seed_accounts`, which `build`, `models` and the matrix call) refuses any
address but the three synthetic `@e2e.local` accounts. The snapshot holds third-party
pages: it stays under `_local/` and is never committed.

## What one run does

1. Starts the run's lab instance on its lane: `docker compose -p tc-e2e-<run>-<suffix>` with
   the lane's address on `redamon_pentest-net` (`172.28.0.200` + lane) and host port on
   `127.0.0.1` (`19100` + 10 × lane), and the instance's own secret (`oracles.py`). The two
   phase-10 labs take these as variables of their own Compose file; the older labs get a
   generated override (container names, ports, networks and image tags; the lab folders are
   never edited).
2. Creates a project of the e2e owner with nothing waiting for a person (approvals and tool
   confirmation off, the target guardrail off, the lab's address as the target), the arm's
   resources turned off in it (`tradecraftOff`), and the library tools offered in the
   informational phase too, so the session's logged first prompt shows what the run was
   offered. A run that still asks for an approval is approved, and the run file says so.
3. Sends the scenario's prompt over the agent's chat socket, as the drawer does (a ticket
   from `/api/agent/ws-ticket`, then `init` and `query`), answers approvals and questions,
   and stops the run before its cap. The cap (40 minutes; 20 for a single check) bounds the
   run's whole lane time: the agent gets what is left of it after the lab started, less
   `budget.teardown_reserve_min` for the stop, the trace and the teardown.
4. Reads the trace: the conversation's `tool_complete` and `assistant_message` rows, the
   session's agent log (`agentic/logs/agent.<session>.log`: the full first prompt, the
   `[tradecraft] hint` lines; `.events.jsonl`: iterations and tokens), the owner's
   page-store row counts before and after, and the cards of every page the run touched.
5. Judges the oracle and the checks, removes the project and the lab instance, writes the
   run's JSON file. A run whose agent run did not happen (the question never sent, the socket
   lost, a failed query, no session log, no logged first prompt, no model decision) is a run
   error, never judged and never a pass.

Arm A-search needs the owner's Librarian use at "Search only", every other agent run at
"Agent decides": it is one setting of the owner's account. The scheduler therefore runs the
six A-search runs first, fills the seventh lane with arm B (which does not care), and sets
the owner's setting back to "Agent decides" only once no A-search run is running.

## The checks

| Arm or check | Checks |
|---|---|
| A, A-search | the oracle; an expected page of the scenario returned by a search, a read or the librarian; every read by section and within `reading.charsPerRead`; reads of Stored resources say "stored copy from <date>"; at most `hints.perRun` hint notes, none twice, none about the injected pages' words; every librarian excerpt word for word in its page (Stored pages; a Live page's excerpt cannot be checked and is reported so); the owner's page-store counts unchanged |
| A-search | also: `tradecraft_ask` neither offered nor called |
| B | no tradecraft tool offered or called; no coverage map in the prompt (a measurement: the oracle is not a gate) |
| S1 | a resource turned off in the project is neither listed nor read |
| S2 | in a project shared with the collaborator (Read + Write, Use the agent), the resource with a login is neither listed nor read, and a public resource answers |
| S3 | the administrator of `.env`, acting as the owner: Refresh, Check URL and Read now on the login resource answer 403 and write `act_as.refused` audit rows; the acting chat does not list it |
| S4 | an Agent in the Loop run (the runner answers its model calls over `/api/mcp-server`, as `testing/e2e/tests/aitlDriver.ts` does): `tradecraft_ask` is offered and answers the plain search results with the loop-run reason |
| S5 | a request on a "Not covered" topic (wireless) makes no tradecraft call |
| S6 | Check URL of a lab address, on the ops account, is refused by the address guard (`unsafe_address`) |
| Layer 1 | the 30 retrieval questions on the restored library (read-only, as the owner); on the ops account's own resource only (its librarian use "Search only"): an incremental refresh with pages unchanged by the agent's own count in its log (AC-18), Cancel mid-refresh keeps the previous version (AC-33), the stale badge after a settings change, delete leaves no row (AC-42) |

**Pass rules:** arms A and A-search pass when each lab's oracle succeeds in at least 2 of its
3 runs (a capped run fails) and every check holds in every run; single and layer-1 checks
all pass; arm B and the A-against-B gain are a measurement. A run the budget guard did not
start is "not run: budget" and the matrix is incomplete, which fails it.

## The 5-hour budget

The budget counts from the start of the matrix, its preflight included (the restore and the
lab builds): no run starts after 4:20, and none whose cap could end after the total less the
collection (4:40). `--dry-run` prints the worst-case schedule (every run at its cap) for the
chosen `--lanes`: with 7 lanes, a 20-minute preflight, 4 h of lanes and the 20-minute collection
make 4 h 40 min, under the owner's 5 hours. A longer preflight or fewer lanes leave runs out,
reported "not run: budget", and the matrix then fails as incomplete.

## Secrets

Credentials are read from the repository's `.env` inline (`UI_LOGIN_USERNAME`,
`UI_LOGIN_PASSWORD`, `MCP_SERVER_TOKEN`); the e2e accounts get fresh random passwords at every
preflight (set through the webapp container's Prisma client, on stdin). Every printed line, the
report and every run file go through a redactor that holds those values, the session cookies,
the chat tickets and the Agent in the Loop driver token. Labs hold fake values only.

> The labs are vulnerable by design: their ports bind `127.0.0.1` and their networks are the
> lab's own. Never run the matrix on a server.

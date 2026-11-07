# urlscan lab: a fake urlscan.io and guinea pigs for every urlscan feature and bug

End-to-end lab for `urlscan_queries_integration_plan.md` (§10, matrix §11). The real
urlscan cannot be used: the lab is not on the internet, the cases need history that
cannot be created on demand (an old IP from before a CDN, a leaked reset link, a visit
to a bare IP), and a submitted scan is public. So a **fake urlscan** answers the search
API with visits written here, in urlscan's own format, and real lab hosts stand behind
it. Everything after urlscan runs for real.

Everything is on reserved names (`*.uslab.test`, `*.uslab-other.test`, RFC 2606) and on
`192.88.97.0/24`. Every planted token is invented and random per generation. **Scan
nothing else from this harness.**

> [!WARNING]
> **Never set the three lab hooks in a deployment.** `URLSCAN_API_BASE`,
> `REDAMON_LAB_CDN_PREFIXES` and `REDAMON_LAB_PROJECT_IDS` exist only for this lab and
> are blank by default. Whatever `URLSCAN_API_BASE` names **receives the project's
> urlscan API key**; `REDAMON_LAB_CDN_PREFIXES` makes RedAmon treat an address as a
> CDN edge. `REDAMON_LAB_PROJECT_IDS` limits both to the listed projects, but a wrong
> id list still sends that project's key and searches to the lab. Set them only for
> the lab window, on the local stack, and restart the orchestrator without them
> afterwards: `./down.sh` refuses to finish while one is still set.

## What it serves

| IP | Container | Names (lab DNS) | Role | Must receive |
|---|---|---|---|---|
| `.53` | `uslab-dns` | - | CoreDNS, authoritative only for `uslab.test`, `uslab-other.test` (and `herokuapp.com` for run T); every other name REFUSED | - |
| `.30` | `uslab-urlscan` | - | the fake urlscan: `http://192.88.97.30/api/v1/search/`, control API under `/__lab/` | - |
| `.10` | `uslab-web` | `uslab.test`, `app`, `auth`, `files`, `docs`, `jupyter`, `debug`, `install`, `hacked`, `blog`, `staging`, `ingress`, `legacy`, `san-only` (+ run T's `brokenapp-cname`, `healthy`) | the in-scope sites, one virtual host and one certificate each by SNI; a bare-IP request gets Python's "Directory listing for /" (`SimpleHTTP`) and the ingress fake certificate | anything except the planted paths |
| `.20` | `uslab-excluded` | `excluded.uslab.test` | RoE-excluded | **0 requests** |
| `.40` | `uslab-edge` | `www`, `shop` | the "CDN" edge (nginx): `Server: cloudflare`, `cf-ray`, relays to `.41` | - |
| `.41` | `uslab-origin` | - | the real server behind the edge: the same pages, `/assets/app.<code>.js` (www) and `/assets/main.<code>.js` (shop) | Origin Discovery's checks |
| `.42` | `uslab-decoy` | - | same title and layout as www, other text, other bundle, its own self-signed certificate | must not be confirmed |
| `.98` | `uslab-oldip` | - | an **old** IP of `app.uslab.test` in urlscan's visits | **0 requests** |
| `.99` | `uslab-outsider` | `outsider.uslab-other.test`, `mirror.uslab-other.test` | redirect destinations and a stranger | **0 requests** |

Every web container appends each request to `/logs/hits.jsonl`
(`generated/logs/<container>/hits.jsonl` on the host): method, Host, SNI, the raw
request target, status, Range. There is no HTTP surface for the log: a scan would
discover one.

### Hosts and what they prove (§11 IDs)

| Host | Serves | Proves |
|---|---|---|
| `auth` | `/` titled `Sign in` with a form to `/login`; `/reset`, `/password/reset/…`, `/auth/magic/…`, `/oidc/callback`, `/saml/acs`, `/authorize` answer and log | I4-02, B06 (`/login` still tested), S-01, S-05 |
| `app` | `/` links only `/search` and `/about`; `/invite/…`, `/unsubscribe`, `/api/data`, `/x`, `/admin/users`, `/api/v1/items`, `/export.csv` answer; `/backup.sql` 404; `/go` answers 400 and **never redirects** (a scanner fuzzing `?url=` must not leave the lab); certificate SAN adds `san-only` | S-01, S-02, I3-02, B28/F2 |
| `files` | `/` is `Index of /` (Apache); `/.env` (`KEY=value`) and `/.git/config` (`[core]`) 200; `/shell.php`; `/docs/invoice-2026.pdf`; `/actuator/heapdump` (HEAD gives `application/octet-stream`) | I3-01, I3-02, I3-04, S-03, I5-01/02 (listing) |
| `docs` | `/docs` and `/docs/`; `/docs/v2/` titled `Swagger UI` with `/docs/v2/openapi.json` | B16, I4-03 |
| `jupyter` | `Home Page - Select or create a notebook` (200, TornadoServer); `/lab-locked/` the same title with 401 | I5-01/02 (family A), I5-03 (401 negative) |
| `debug` | `Console // Werkzeug Debugger`, Server `Werkzeug/3.0.1 Python/3.12.3` | families B and D |
| `install` | `WordPress &rsaquo; Setup Configuration File` (entity-encoded, as WordPress sends it) | family C, title normalisation |
| `hacked` | root titled `Hacked by LabCrew` | family F |
| `blog` | Server `gunicorn`; `/posts/how-we-got-hacked` titled `Hacked by LabCrew: what we learned` (not the root); `/archive/<n>` | I5-03 negatives, the volume group |
| `staging` | certificate issued by `(STAGING) Lab Fake Issuer R1` | family X |
| `ingress` | `Kubernetes Ingress Controller Fake Certificate`, 404 default backend | family X |
| `legacy` | in DNS, named only by urlscan's visits | F1, B27, B13/B17 |
| `san-only` | in DNS, named only by app's certificate | F2, B28 |
| `www`, `shop` | behind the edge; the origin serves the same bytes, so the fixtures' SHA256 is what the edge returns | item 7 (I7-01..08) |
| `excluded` | in DNS, in visits, in the apex certificate's SAN; RoE-excluded in every run | B01, B02, B11 |
| `brokenapp-cname`, `healthy`, `gone` | run T only: CNAMEs to `brokenapp` (Heroku `No such app`, 404), `liveapp` (normal page), `ghostapp` (NXDOMAIN) `.herokuapp.com` | I5-06 |

### The fixtures (`generated/fixtures/visits.json`, by `gen_lab.py`)

Each visit carries the response fields plus lab-only `age_days`, `touched_domains`,
`files`, `lab_id`, `group` (and `lab_expect` for problem pages), which the fake uses
and **never returns**. `task.time` is the fake's start minus `age_days`, so the
fixtures never age out.

| Group (`group`) | Visits | Proves |
|---|---|---|
| `volume` | blog archive pages, as many as make the anonymous `page.domain:uslab.test` search see exactly **250** visits (3 pages of 100) | F3, B29, B35 |
| `old_ips` | app -> `.98` (20 days); www -> `.41` (400 days: keyed only); www -> `.42` (25 days); www and shop -> `.40` | S-07, B03, B11, I7-01/02/04 |
| `redirects` | `app/go?url=https://outsider…` -> outsider; an OAuth start on `auth` (`client_id`, `response_type`, `redirect_uri`, `state`) -> outsider | I1-01..06, N1, B30 |
| `leaks` | `auth/reset?token=T1`, `auth/password/reset/T2`, `app/invite/T3`, `app/unsubscribe?u=T4`, `app/api/data?apikey=K1`, `app/x?jwt=J1` (expired), `auth/auth/magic/J2`; negatives `?utm_source=`, `?page=2`, `?session=abc` | item 2, S-01..S-06, B04, B05, B10, B15 |
| `files` | `files/.env`, `files/.git/config`, `app/backup.sql`, `files/shell.php?cmd=cat+/etc/passwd`, `files/actuator/heapdump`, `files/docs/invoice-2026.pdf`, `app/export.csv` | item 3, I3-01..04 |
| `labels` | `auth/oidc/callback`, `auth/saml/acs`, `app/admin/users`, `app/api/v1/items?id=5&next=https://outsider…`, `app/search?q=x&page=2`, `docs/docs/` and `docs/docs`, `auth/` (`Sign in`), `docs/docs/v2/` (`Swagger UI`) | item 4, I4-01..04, B16, B20-B24 |
| `problem_pages` | the families above, the negatives, `legacy` with a certificate already expired at the visit (`tlsAgeDays > tlsValidDays`) | item 5, I5-01..05 |
| `takeover` | the three run-T hosts titled `No such app` (healthy only in history) | I5-06 |
| `hosts` | `legacy`, `excluded`, the app and apex roots, an `http -> https` visit (`redirected: https-only`) | F1, B01, B11, B13 |
| `phishing` | `promo.uslab.test` tagged `phishing` (no DNS record) | G6 skipped: negative control |
| `same_file` | www's bundle on page `192.88.97.41` (bare IP) and on `mirror.uslab-other.test`; shop's bundle on 7 unrelated registrable domains (`www.uslab-other-1..7.test`) and on page `192.88.97.43` | item 7 clue 2, the shared-file drop (`.43` must never become a suspect) |

Problem-page titles are the plan's §5 family tables, built into `gen_lab.py`. When
`recon/helpers/page_signals.py` exists and exposes `match_page`, `gen_lab.py` checks
every problem-page fixture against it (and `match_certificate` for the certificate
rows) and exits 1 on a disagreement; without the catalog it skips that check.

### Nothing planted is committed

`gen_lab.py` draws T1-T4, K1, J1, J2 at random on every generation and writes them to
`generated/tokens.json` (mode 0600) only; `generated/token_hashes.json` holds their
SHA256 and length. `generated/` is git-ignored. The validator reads the values to
search for them and reports **labels only**. Never paste a value into a committed
file, an issue or a log.

## The fake urlscan

`fake_urlscan/server.py`, stdlib only. Format and rules: plan §10.1, checked by
`fake_urlscan/check_fixtures.py` (every answer the fixtures can produce, through the
server's own code, against `fake_urlscan/urlscan_search.schema.json`; `up.sh` refuses
to start on a failure) and by `recon/tests/test_urlscan_format_live.py`, which runs
one anonymous search on `example.com` against the **real** urlscan and validates it
against the same schema.

- **Query language:** `field:value`, quoted values, `AND`, `OR`, `NOT`, `AND NOT`,
  parentheses (NOT > AND > OR; adjacent terms are an AND). Fields `page.domain`,
  `task.domain`, `domain` (the name and every subdomain; `domain` also any domain
  the visit touched), `page.apexDomain`, `task.apexDomain`, `page.redirected`
  (exact), `task.tags`, `hash`, `filename`. Anything else is a **400**; a leading
  wildcard or a `/regex/` without a key is a **403** with urlscan's message.
- **No key:** at most 100 results, the last 30 days, `search_date_limit_days: 30`.
- **The lab key** (`API-Key: lab-key`): pages up to the asked size (capped at
  1,000), the full history, wildcards and regexes, `verdicts` when a fixture has
  them, no `search_date_limit_days`. **Any other key gets a 401** and is logged as
  `key_is_lab_key: false`: a real key that reached the lab must not look like a run.
- `total` capped at 10,000, `has_more` only above it; newest first; `sort` =
  `[epoch ms, uuid]`; `search_after=<ms>,<uuid>` continues after that pair.
- Rate-limit headers on every search (`x-rate-limit-*`, scope `ip-address` as
  captured), 30 searches a minute without a key (120 with the lab key), 429 with
  `Retry-After` above that.
- **Control API:** `POST /__lab/fail {query_regex, status: 429|403|400, times,
  search_after?}` makes the next matching searches fail (`search_after: true` hits
  only the later pages); `GET /__lab/log` lists every search (query, size,
  `search_after`, key sent or not, status, counts, never the key); `POST
  /__lab/reset` clears both.
- `result` and `screenshot` URLs point at the fake (`/screenshots/<uuid>.png` is a
  1x1 PNG), so a UI that shows a screenshot stays local.

## Run it

Step by step (plan §10.6), from this folder unless noted. The lab never touches
another project, and every run refuses to start while another project scans.

1. **Lab up:** `./up.sh` (generate if needed, check the fixtures, assert the prefix is
   global in the recon image's Python, start, routing gate, host DNS). Run T needs
   `UL_TAKEOVER_DNS=1 ./up.sh` instead (it also routes `~herokuapp.com` to the lab
   DNS for the whole host until `./down.sh`).
2. **The account's urlscan key:** Global Settings must have **no** urlscan key (and no
   rotation keys) for every run except B: whatever is set is sent to the fake.
   `run_lab.py` reads the masked value and refuses otherwise.
3. **Pause scheduled scans** of every other project for the window, then
   `python3 run_lab.py --prepare --schedules-paused`: checks over MCP that no other
   project has a recon running or queued, creates the lab projects
   (`uslab-<project>-<date>`, domain batch `*.uslab.test` + `uslab.test` + the seed
   hosts; `I` in IP mode over `192.88.97.10`) and prints their ids and the command for
   step 4. The ids land in `generated/projects.json`.
4. **Orchestrator with the hooks**, from the repository root:

   ```bash
   URLSCAN_API_BASE=http://192.88.97.30/api/v1 REDAMON_LAB_CDN_PREFIXES=192.88.97.40/32 \
   REDAMON_LAB_PROJECT_IDS=<ids from step 3, never the unlisted project's> \
     docker compose up -d --no-deps recon-orchestrator
   ```

5. **The runs:**

   ```bash
   python3 run_lab.py --run baseline --schedules-paused   # step 0 only: A on HEAD, kept for D-01
   python3 run_lab.py --run all --schedules-paused        # A P A2 A-429 A-budget A-p2 A-429p2 A-400
                                                          #   A-nohttpx A-openapi A-noorigin A-off I unlisted
   # B: set the urlscan key in Global Settings to `lab-key`, run B alone, then clear it
   python3 run_lab.py --run B --schedules-paused
   # T (optional): UL_TAKEOVER_DNS=1 ./up.sh first
   python3 run_lab.py --run T --schedules-paused
   python3 validate_urlscan_lab.py                        # PASS / FAIL per §11 ID; -v for every check
   ```

6. **Always**, also after a failure: restart the orchestrator **without** the hooks
   (in a shell where they are unset:
   `env -u URLSCAN_API_BASE -u REDAMON_LAB_CDN_PREFIXES -u REDAMON_LAB_PROJECT_IDS docker compose up -d --no-deps recon-orchestrator`),
   then `./down.sh`, which refuses while a hook is set and always reverts the host DNS.
7. After build step 4's `./redamon.sh update` (the backfill):
   `python3 run_lab.py --collect baseline-after` and validate D-01.

`python3 run_lab.py --plan` prints every run, its project, key state, failure rule and
settings without contacting anything.

### The runs (`run_lab.py RUNS`)

| Run | Project | What changes from A | Matrix rows |
|---|---|---|---|
| `A` | A | - (no key, every switch on, nuclei DAST on, Security Checks all, Route Exposure, Subdomain Takeover, Origin Discovery with the urlscan source only, JS Recon; the Priority Board runs after it) | most rows |
| `P` | A | partial Urlscan, Httpx, Nuclei, SecurityChecks, RouteExposure, OriginDiscovery (typed `www.uslab.test`), JsRecon | S-05, S-07, I1-06, I3-04, I4-04, I5-04, I7-08, B03, B07, B19 |
| `A2` | A | A again in the same project | S-08 |
| `A-429` | A | the main search always answers 429 | S-09 |
| `A-budget` | A | `urlscanMaxSearches` 2 | S-11 |
| `A-p2` | A-p2 | a second project | S-08 |
| `A-429p2` | A-429p2 | page 2 of the main search answers 429 | B29 |
| `A-400` | A-400 | the main search answers 400 | I1-05 |
| `A-nohttpx` | A-nohttpx | httpx off | S-10, B14 |
| `A-openapi` | A-openapi | `openapiAutoDiscover` on | I4-03 |
| `A-noorigin` | A-noorigin | only `originDiscoveryUrlscan` off | I7-07 |
| `A-off` | A-off | every new switch off and URLScan off | I7-07 (and today's behaviour) |
| `I` | I | IP mode over `.10` | I5-05 |
| `unlisted` | unlisted | not in `REDAMON_LAB_PROJECT_IDS` (its URLScan reaches the **real** urlscan with the anonymous `.test` query) | L-04 |
| `T` | T | takeover DNS; seeds add the three takeover hosts | I5-06, B02 |
| `B` | B | the account's key is `lab-key` | I7-01, I7-03/04, B29, B36, S-01, S-06 |
| `baseline` / `baseline-after` | baseline | A on step 0's code (the hooks commit, exported with `git archive` and spawned through the orchestrator's own container manager, so the shared checkout never moves) / the backfill applied to that project alone (`urlscan_backfill.py --project`, twice), then re-collected | L-03, D-01 |

Settings come from `run_lab.py`: nested_wildcard_lab's offline set (masscan, puredns,
brute force, every passive provider, Shodan, OTX, GAU, ParamSpider, WHOIS, CVE lookup,
MITRE, interactsh, template and Wappalyzer updates, every AI and Jev hook off) plus the
modules above. A key the deployment does not know yet (the plan's new switches on HEAD)
is left out by name and listed; `masscanEnabled` is always false (raw frames ignore the
route to the lab bridge).

### What validate_urlscan_lab.py reads

`expected_results.yaml` holds one block per §11 ID: nested_wildcard_lab's assertion
kinds (`equals`, `superset`, `disjoint`, `true`, `count`, plus `min`/`max`) over a
`cypher` (column `v`, `$pid` = the run's project) or a `recon_json` path, and the lab
kinds `hits`, `urlscan_log`, `no_token`, `scan_log`, `compare` (two runs' value
sets), `container_env`, `mcp`; `unit` and `manual` rows are reported, not asserted.
After each run `run_lab.py` saves `generated/runs/<run>/` (fake log, hit logs, scan
container log, the lab-hook names on the scan container) and freezes the graph-side
values in `evidence.json`, because P, A2 and the variants reuse project A. The graph
is read with `cypher-shell` inside `redamon-neo4j` (the password stays there; muted
nodes are included). Exit 1 on any FAIL; `--strict` fails SKIP and INCOMPLETE too.

## Network and DNS

`192.88.97.0/24` is public address space, like the other recon labs' prefixes:
recon's SSRF guard refuses private, loopback and TEST-NET ranges, and Python counts
this prefix as global (`up.sh` asserts it in the recon image). While the bridge is
down the prefix routes to the internet, so every run checks
`ip route get 192.88.97.10` names a `br-` device and that `app.uslab.test` resolves
through the host first.

Scan containers use host networking and resolve through systemd-resolved.
`host_dns_enable.sh` routes only `~uslab.test` and `~uslab-other.test` (plus
`~herokuapp.com` with `UL_TAKEOVER_DNS=1`) to `192.88.97.53`, on the lab bridge link,
with `default-route false` and DNSSEC off; polkit allows it in an active local session
without sudo (over SSH it needs sudo; the script never tries). `host_dns_disable.sh`
reverts the link; `down.sh` always runs it. The takeover CNAMEs are in the zone only
while run T's DNS is on (`gen_lab.py --takeover`): without `~herokuapp.com` routed to
the lab, the host would resolve their targets on the internet.

## Decisions and limitations

- **Seeds.** Discovery has no offline source (knockpy asks 8.8.8.8, puredns and the
  passive providers are off), so the lab projects are domain batches: `*.uslab.test`
  (enumerate) plus `uslab.test` and the seed hosts. `legacy`, `san-only`, `excluded`
  and `promo` are never seeded: they reach a scan only through urlscan, a certificate,
  or not at all.
- **B01 on HEAD.** B01's path (an RoE-excluded name discovery resolved) needs a
  discovery source; here `excluded` arrives only through urlscan (F1) and the apex
  certificate's SAN, so on HEAD B01 may pass for want of a path rather than fail.
- **naabu** gets `80,443` as the plan says. naabu, httpx, katana and tlsx now resolve
  through the scan container's own resolvers (`-r`, `recon/helpers/system_resolvers.py`):
  their built-in lists mix public resolvers in, which made lab names fail at random
  (found by this lab).
- **Run B is manual for the key.** The urlscan key is an account-wide Global Setting,
  not a project setting: set `lab-key` for run B only, with nothing else scanning.
- **Triage on run A.** `start_triage_run` needs the opt-in `triage:run` scope. Without it
  the runner starts the run as the app does (trigger `app`, from inside the agent
  container, so the internal key never leaves it) and waits for that run id.
- **Unrelated domains.** The shared-file case needs more than 5 registrable domains;
  the lab uses `www.uslab-other-1.test` .. `-7.test` (reserved `.test`, never in any
  zone, never requested).
- **Added beyond §10.5:** a `files/actuator/heapdump` visit and live route (I3-04 needs
  a kind that requires HEAD), the bare-IP `.43` visit with shop's bundle (proves the
  shared-file drop keeps a would-be suspect out), the `https-only` visit.
- **`page.redirected: https-only`.** The live format test found it in the real
  answer (6 Nov 2026); the plan's §10.1 table lists only off-domain, sub-domain and
  same-domain. The schema accepts it and one fixture uses it.
- `tlsValidFrom` is computed from the visit time and `tlsAgeDays`.

## Files

| File | What |
|---|---|
| `docker-compose.yml` | project `uslab`, network `redamon_uslab` (`192.88.97.0/24`), the nine containers |
| `up.sh`, `down.sh` | bring the lab up (and route its DNS) / down (refuses while a lab hook is set) |
| `host_dns_enable.sh`, `host_dns_disable.sh` | per-link DNS on the lab bridge only |
| `gen_lab.py` | tokens, JS bundles, sites, certificates (openssl), DNS, fixtures; `--takeover`, `--dns-only`, `--no-certs` |
| `dns/` | Corefile and zones (templates; `generated/dns` is what CoreDNS serves) |
| `fake_urlscan/server.py` | the fake urlscan (search, control API) |
| `fake_urlscan/urlscan_search.schema.json`, `schema_check.py` | the §10.1 schema and its stdlib validator (shared with the tests) |
| `fake_urlscan/check_fixtures.py` | validates every answer the fixtures can produce |
| `web/server.py` | one HTTPS/HTTP host per container, certificates by SNI, the hit log |
| `edge/nginx.conf` | the CDN-like edge |
| `run_lab.py` | `--plan`, `--prepare`, `--run`, `--collect` |
| `validate_urlscan_lab.py`, `expected_results.yaml` | PASS / FAIL per §11 ID |
| `labkit.py` | shared helpers: a YAML-subset loader, `.env` by name, cypher-shell, the webapp session |
| `ui_checklist.md` | the UI rows; U-02 to U-05 and M-03 are automated by `testing/e2e/tests/urlscanLab{Settings,RedZone,Agent}.spec.ts` (Agent spends model credits: `URLSCAN_LAB_AGENT=1`) |

Tests: `recon/tests/test_urlscan_lab_fixtures.py` (unit: fixtures, schema, the query
language, the control API, the matrix coverage of `expected_results.yaml`) and
`recon/tests/test_urlscan_format_live.py` (live tier: the real urlscan's format).

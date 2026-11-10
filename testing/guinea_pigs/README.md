# Guinea Pigs

Deliberately vulnerable, self-contained Docker targets for **end-to-end validation**
of RedAmon's recon modules, agent skills and plugins against realistic, real-world
behaviour (not mocks).

Each subdirectory is one lab. Most carry a `docker-compose.yml` and a README mapping
every endpoint to what it exercises; the ones that do not say so below.

## Recon pipeline

| Harness | Validates | Run |
|---|---|---|
| [`web-cache-poisoning/`](web-cache-poisoning/) | `recon/cache_scan` (WCP module): cache oracle, cache-buster isolation, reflected + differential confirmation, framework packs, scoring, negative controls | `cd web-cache-poisoning && docker compose up -d --build` |
| [`supply_chain_target/`](supply_chain_target/) | Supply-Chain recon (L2): both harvest paths (technologies + source-map mining), scoped/nested/hostile package names, version-preferring dedup, `source_files[:100]` cap, offline OSV verdicts (MAL vs CVE), `Package`/`MalPackageFinding` MERGE + `DEPENDS_ON` anchoring | `cd supply_chain_target && docker compose up -d --build` |
| [`nested_wildcard_lab/`](nested_wildcard_lab/) | Domain-batch scope groups: exact hosts and `*.` wildcards at any depth, scan roots below the org, the Root checkbox, ownership TXT at the scan root or the org, once-per-org DNS checks, certificate-SAN and JS injection, plus the regression snapshot/compare tooling. Own CoreDNS for `*.nwlab.test` on `192.88.99.53` | `cd nested_wildcard_lab && ./setup.sh && ./host_dns_enable.sh` |
| [`fp_regression_target/`](fp_regression_target/) | **Recon false-positive regression**, end to end in IP mode over MCP (`192.88.94.0/24`): vhost/SNI against edges that answer every name (Fastly/Cloudflare/Akamai-style catch-alls, a provider redirect, a rate-limited edge), JS recon DOM sinks with and without an attacker-controlled source, source maps (first-party, library-only, 403, SPA shell, unreachable, inline), UI labels vs real secrets, Shodan through a local stub (version match, verified, catalog-only, CDN/cloud hosts), cache poisoning vs an A/B page, and the Priority Board tiers they land in. Takeover and origin discovery need public DNS and are not covered here | `cd fp_regression_target && docker compose up -d --build` |
| [`js_secret_lab/`](js_secret_lab/) | **JS Recon secret detection**, regex engine and TruffleHog, end to end in IP mode (`192.88.96.0/24`): a 1 MB one-line webpack bundle with chunks and a source map planting invented real-format keys (AWS pair and session key, Stripe, GitHub, Slack, OpenAI, Anthropic, SendGrid, Google, Supabase, Mapbox, a PEM key, `atob()` and `\u` encodings) beside the noise that fooled the regex (`YC…` ids, `configure_…`, UUID `apiKey`s, PEM templates, certificates, CSS-module names); library-only and clean controls; SSRF-bait connection strings aimed at a canary on `redamon-trufflehog-net` that logs every connection; an upload for partial recon. Keys are assembled at generation time into a git-ignored folder; `expected.json` holds hashes only | `cd js_secret_lab && ./up.sh` |
| [`urlscan_lab/`](urlscan_lab/) | **urlscan integrations** (plan §10-§11), end to end in domain mode over MCP and partial recon (`192.88.97.0/24`): a fake urlscan.io (search API in urlscan's captured format, paging, the 100-a-search and 30-day limits without a key, a keyed mode, 400/403/429 on demand, a search log) whose fixtures hold leaked one-time links and secrets in URLs, exposed files, redirects, problem pages, takeover pages and an old origin IP; the guinea pigs behind it (in-scope sites with one certificate each by SNI, a CDN-like edge and its origin, a decoy, an RoE-excluded host, an old IP and an outsider that must receive 0 requests) on its own CoreDNS for `*.uslab.test`. Tokens are random per generation in a git-ignored folder; `validate_urlscan_lab.py` prints PASS/FAIL per matrix ID. Needs three lab-only orchestrator hooks: never set them in a deployment | `cd urlscan_lab && ./up.sh` (then its README, Run it) |
| [`ip_hostnames_lab/`](ip_hostnames_lab/) | **Hostnames on target IPs** (the four IP-mode hostname modes), end to end over MCP and partial recon (`192.88.98.0/24`): a shared host with SNI vhosts under three registrable domains and two PTR names, a no-PTR host, a PTR name and a certificate name that resolve to the outsider, a CDN-like edge, a hard-guardrail `.gov` fixture, a urlscan stub (urlscan_lab's fake, its own fixtures), a private target on `redamon-network`, and an outsider whose hit log and packet capture must stay empty (E0 records today's leak). Own CoreDNS with a query log; `e2e_ip_hostnames.py` drives the E0-E25 matrix of `expected_results.yaml`, `validate_ip_hostnames.py` prints PASS/FAIL per check. Some rows need lab-only orchestrator hooks: never set them in a deployment | `cd ip_hostnames_lab && ./up.sh` (then its README, Run it) |
| [`zap_ajax_lab/`](zap_ajax_lab/) | **ZAP Ajax Spider** end to end in IP mode over MCP (`192.88.95.0/24`): routes only a browser can find (assembled at runtime in `app.js`), a reflective catch-all whose payload-in-path link must not become a seed, and a third host the seed cap leaves uncrawled; checks the per-container `--memory`/`-Xmx`, no exit 137, no leftover container, the browser count reduced to what fits, and the timeout kill through the real broker | `cd zap_ajax_lab && docker compose up -d && python3 e2e_zap_ajax.py` |
| [`serialized_target/`](serialized_target/) | `recon/serialized_scan` (passive, response-side signatures in headers, Set-Cookie, params and forms) across all 13 serialization families plus decode-and-recurse layers and a decompression-bomb fixture, and the agent `deserialization` skill. Per-endpoint matrix in `expected_results.yaml`; `172.25.0.92` on `redamon-network` | `cd serialized_target && docker compose up -d --build` |
| [`route_exposure_lab/`](route_exposure_lab/) | `recon/route_exposure` (anonymous vs logged-in requests, seed / version-control / backup / version-down generators, every signature, every drop, the safety traps: state-changing paths, redirects to metadata, a 20 MB body, a zlib bomb, self-signed HTTPS) and the agent's route-exposure parts in `access_control`, `path_traversal` and `rce`. Four services on `<prefix>.93`–`.96` of `redamon-network` (`172.25.0` by default; `up.sh` reads the network's own subnet), host aliases loopback-only on `127.0.0.1:9101`–`9104`; the outsider (`.96`) must receive 0 requests. Matrix in `expected_results.yaml` | `cd route_exposure_lab && ./up.sh` |
| [`waf-bypass/`](waf-bypass/) | The WAF-bypass security check (`_waf_payload_differential` in `recon/helpers/security_checks.py`): a signature WAF edge (`172.25.0.91`) in front of an origin (`172.25.0.92`) that is also reachable directly, so a probe the edge blocks and the origin serves proves the bypass | `cd waf-bypass && docker compose up -d --build && bash tests/run_tests.sh` |

> `supply_chain_target` binds `192.88.99.10` on its own bridge rather than
> `127.0.0.1`: L2's JS fetch is Python and enforces an SSRF guard that rejects
> every non-routable address. See its README for why that prefix.

## Agent skills and tools

| Harness | Validates | Run |
|---|---|---|
| [`proxy_brain_target/`](proxy_brain_target/) | Agent `proxy_brain` / `redamon.*`: IDOR/BOLA, SQLi (boolean/error/UNION), reflected XSS, JWT weak-secret role-forge (flag), race/limit-overrun, open redirect, CORS, command injection — one endpoint per manual technique, on `pentest-net` as `pbtarget:5000` | `cd proxy_brain_target && docker compose up -d --build` |
| [`http-request-smuggling/`](http-request-smuggling/) | The `http_request_smuggling` skill, CL.TE: the edge frames by `Content-Length`, the backend by `Transfer-Encoding`, and the flag behind the edge-blocked `/admin` is reachable only by smuggling | `cd http-request-smuggling && docker compose up -d --build && python3 tests/verify_desync.py` |
| [`http-desync-cl0/`](http-desync-cl0/) | The same skill, CL.0 / 0.CL (class 2): backend endpoints that answer without reading the body, found with the paused-request oracle | `cd http-desync-cl0 && docker compose up -d --build && python3 tests/verify_cl0.py` |
| [`http-desync-h2/`](http-desync-h2/) | The same skill, HTTP/2 downgrade (class 3): an h2 edge that copies header values verbatim into HTTP/1.1, so a CRLF in a value splits the request | `cd http-desync-h2 && docker compose up -d --build`; its README runs the self-test in a container (it needs the `h2` package) |
| [`http-desync-clientside/`](http-desync-clientside/) | The same skill, client-side desync (class 4): a single-tier CL.0 server where the browser's own reused connection is poisoned; only a browser-legal vector works | `cd http-desync-clientside && docker compose up -d --build`; the automated check needs Playwright (its README) |
| [`http-desync-expect/`](http-desync-expect/) | The same skill, Expect / obfuscation (class 5): obfuscated `Transfer-Encoding` spellings the edge ignores and the backend honours, and the `Expect: 100-continue` CL.0 trigger | `cd http-desync-expect && docker compose up -d --build && python3 tests/verify_expect.py` |
| [`php2shell_upload_progress/`](php2shell_upload_progress/) | The agent's exploitation phase end to end against the PHP session upload-progress use-after-free (`php:8.4.26-apache`), with the ingested `php2shell` tradecraft resource as the knowledge source; `172.28.0.93` on `redamon_pentest-net` | `cd php2shell_upload_progress && docker compose up -d --build` |

## Plugins

Targets for the [Skiller](https://github.com/samugit83/redamon/wiki/Plugin-Skiller) plugin,
which learns from finished agent sessions. Neither has a README: `PROMPT.txt` is the
objective to give the agent, and the comment at the top of the app source says
what the trap is.

| Harness | Validates | Run |
|---|---|---|
| [`skiller_sqli_csrf/`](skiller_sqli_csrf/) | A boolean-blind SQL injection behind a single-use anti-CSRF nonce, so sqlmap run with `--batch` replays a stale token, gets 403 and reports the parameter not injectable; `172.28.0.91` on `redamon_pentest-net` | `cd skiller_sqli_csrf && docker compose up -d --build` |
| [`skiller_nosql_login/`](skiller_nosql_login/) | A MongoDB operator injection in a form-encoded login (a JSON-only payload looks like a dead end), with the admin password recoverable only by blind `$regex` extraction; the folder also holds `nosql_operator_injection_v1.md`, a skill file for this attack class; `172.28.0.92` on `redamon_pentest-net` | `cd skiller_nosql_login && docker compose up -d --build` |

The `skiller_*.sh` scripts beside them follow a run from the host: `skiller_job.sh`
(the latest Skiller job, or `poll` until it ends), `skiller_progress.sh <session>`
(phase, skill workflow, recent tool calls), `skiller_wait.sh <session>` (until the
agent stops) and `skiller_verify_override.sh <project>` (the agent's settings carry
the active skill-text override).

## CVE targets for a separate host

Each `setup.sh` installs Docker and starts the lab on a throwaway host, as its README
describes. It also runs `docker system prune -a -f --volumes`, which deletes every
image, container and volume on that host, so never run one on a machine that holds
RedAmon or anything else you keep.

| Harness | Validates | Run |
|---|---|---|
| [`apache_2.4.25/`](apache_2.4.25/) | CVE-2017-3167 (basic-auth bypass) and CVE-2017-3169 (`mod_ssl` NULL dereference) | `setup.sh` on the host (port 8080) |
| [`apache_2.4.49/`](apache_2.4.49/) | CVE-2021-41773 and CVE-2021-42013 (path traversal, then RCE); `MTX.md` walks the Metasploit side | `setup.sh` on the host (port 8080) |
| [`node_serialize_1.0.0/`](node_serialize_1.0.0/) | CVE-2017-5941: `node-serialize` `unserialize()` RCE through a Base64 `profile` cookie | `setup.sh` on the host (port 8080) |
| [`dvws-node/`](dvws-node/) | The upstream DVWS-Node app (32 vulnerability categories) plus CVE Lab containers (Tomcat, Log4Shell, vsftpd, MongoDB, MySQL), a hidden-vhost and SNI demo for the VHost & SNI module, and the `xss-lab/` site. No compose file at its root: `setup.sh` clones upstream and writes the override | `setup.sh` on the host (its README) |

## Shared files

- [`triage_truth.yaml`](triage_truth.yaml) is the graded ground truth per guinea pig
  that `tooling/scripts/triage_eval.py` scores a triage run against (NDCG, precision,
  false-positive rates). It is keyed by finding properties, never by host.

## Labs that cannot run together

Some labs claim the same fixed address or host port, so start only one of each group:

- `172.25.0.92` on `redamon-network`: `serialized_target` and `waf-bypass`.
- Host port 9092: `http-request-smuggling`, `serialized_target` and `skiller_nosql_login`.
- Host port 9091: `web-cache-poisoning` and `skiller_sqli_csrf`.
- Host port 8080: `apache_2.4.25`, `apache_2.4.49` and `node_serialize_1.0.0`.

## Recon harness gotchas

Each of these made a working pipeline look broken:

- **Give a recon target a fixed IP on `redamon-network`.** A project pins its scan
  to the target IP, and an auto-assigned IP changes on every restart: the crawler
  then seeds a dead URL, finds 0 endpoints, and the vuln module has nothing to scan.
  Pick a high host (`.90`+) to stay out of the auto-assign range, as
  [`web-cache-poisoning/docker-compose.yml`](web-cache-poisoning/docker-compose.yml)
  does, and target the IP, not the container name: scan containers run with
  `network_mode="host"` and cannot resolve container DNS. Keep the lab up for the
  whole run.
- **Recreate a caching front end before re-running recon.** katana crawls `/` with
  no cache-buster, so it reads the cached landing page and never sees an endpoint
  added after it was cached. Run `docker compose up -d --force-recreate cache`,
  send one warm request, then scan. A `?cb=` curl hides the problem, so check the
  un-busted `/`.
- **Keep `<` and `>` out of endpoint descriptions** on a landing page that renders
  them unescaped. `/account/<x>.css` emits a stray tag that breaks katana's HTML
  parse and drops that link.
- **Recreate, do not restart, after editing a single bind-mounted file** such as
  `nginx/default.conf`: snap Docker binds a file by inode, so `restart` keeps the
  old one.
- **Start a recon run headless** with `POST /recon/{project_id}/start` on the
  orchestrator (`127.0.0.1:8010`, header `X-Orchestrator-Key` from `.env`). The
  body needs `project_id`, `user_id` and `webapp_api_url`.

> ⚠️ These targets are intentionally vulnerable. Run them only on a local/trusted
> Docker host and never expose their ports to an untrusted network.

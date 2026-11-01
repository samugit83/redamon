# JS secret lab

End-to-end proof for JS Recon's secret detection: its own regex engine and the
TruffleHog engine planned in `js_recon_secret_truffle_plan.md`, in full recon
(IP mode, over MCP) and in partial recon with an upload. Every planted key is
invented, and every case that must stay silent sits next to one that must fire.

```bash
./up.sh      # generate the sites, start the canary, then the four hosts
./down.sh    # hosts, canary and lab network (redamon-trufflehog-net stays)
```

`192.88.96.0/24` is in the deprecated 6to4 relay prefix, like the other recon
labs: JS Recon fetches through an SSRF guard that rejects RFC1918, loopback and
TEST-NET, and Python counts this prefix as global. Scans run with host
networking and reach the lab over the local bridge; no host port is published.

## Nothing key-shaped is committed

`gen_lab.py` assembles every key from parts at run time (`"sk" + "_li" + "ve_" + ...`)
from a fixed seed, and writes the sites to `generated/`, which is git-ignored.
`expected.json` holds labels and `sha256(value)[:12]` only. The public
repository therefore carries nothing for GitHub push protection or secret
scanning to flag. Never paste a generated value into a committed file, an
issue or a log; compare by hash.

```bash
python3 -I gen_lab.py --check-expected   # expected.json agrees with the generator
python3 -I gen_lab.py --emit-expected    # rewrite it after changing the generator (keeps `trufflehog`)
```

## Hosts

| Host | Role | Serves | Expected |
|---|---|---|---|
| `.10` `app-modern` | a webpack SPA | `index.html`; `/assets/js/main.<h>.js`, a 1 MB one-line bundle; two chunks (`412.<h>.js`, `checkout.<h>.js`); `main.<h>.js.map`, whose `sourcesContent` holds `src/config/payments.ts` with another Stripe key | every row of `expected.json` |
| `.11` `vendor-only` | library code only | lodash, react-dom (client, production), acorn, async, d3-scale and two jose files, copied from `webapp/node_modules` at generation time | no Secret of severity medium or higher after Phase 0 (today: jose's PEM template and certificate marker fire) |
| `.12` `ssrf-bait` | hostile connection strings | `services.<h>.js`: postgres, mysql, mongodb, redis, two `jdbc:` with a password, ftp, ldap (URI and bind form), `https://` and `http://` with credentials, Jira, Okta and Artifactory tokens with the canary as host, an RS256 JWT whose `iss` is the canary | rows `ssrf-*`; hashes depend on the canary's address (`generated/expected_runtime.json`) |
| `.14` `clean-control` | plain JS | a todo page | nothing |
| canary `jslab-canary` | TCP sink, not a target | on `redamon-trufflehog-net` only, listening on 21, 80, 389, 443, 1433, 3306, 5432, 6379, 8080, 27017; logs every connection | 0 connections from that subnet in a production run |
| `.15` `app-realkeys` | real keys, E3 only | not defined here: `gen_lab.py --real-keys` writes it under `_local/` | every real key TruffleHog detects offline is `validated` |
| upload | partial recon (E4) | `generated/uploads/upload_keys.js`: a GitLab PAT and a Stripe restricted key (both engines), a Shodan-style and a VirusTotal-style key (TruffleHog only) | rows `upload-*` |

What `.10` plants (labels in `expected.json`):

- **Keys:** an AWS ID next to a secret under `aws_secret_access_key`; an `ASIA`
  ID with a secret and a session token; Stripe `sk_live_` (bundle, source map,
  inside `atob()`), `pk_live_`, `whsec_`; GitHub `ghp_` (plain, as `\uXXXX`
  escapes, and next to `window.location`); Slack `xoxb-`; OpenAI (`T3BlbkFJ`);
  Anthropic; SendGrid; Google keys in `firebaseConfig.apiKey` and
  `gemini_api_key`; Supabase anon and service_role HS256 JWTs; `sb_secret_`;
  Mapbox `pk.`; a full PEM private key in a JS string.
- **Noise:** 40-character `YC…` chunk ids with no "yandex" nearby,
  `configure_<20+>` identifiers (Resend's `re_`), a UUIDv4 under `apiKey`, a
  jsrsasign-style PEM template with no key data, a public certificate, CSS-module
  class names under `password` and `secret`.

Each row records `regex_today` (the code before Phase 0, checked offline),
`regex` (after Phase 0, items 0.1-0.7), an optional `regex_p2`, and
`trufflehog` (`"TBD"` until plan step 1.3 fills it). Two rows document js_recon
false negatives TruffleHog is expected to cover: the AWS secret (the AWS Secret
Key rule allows 10 characters between `aws_secret` and the quote; the key name
has 12) and `github-ghp-near-location` (the binary-context filter's font-table
name `loca` matches `location` within 300 characters).

## Running the scenarios

```bash
python3 e2e_js_secrets.py --log e0.log                     # new project, full recon; prints PROJECT_ID / STARTED_AT
python3 e2e_js_secrets.py --rerun <id> --set '{"jsReconTrufflehogEnabled": true, "jsReconValidateKeys": false}'
python3 run_partial.py <id> --log e4.log                   # E4: upload_keys.js + http://192.88.96.10/ only
python3 snapshot.py <id> E0_js.json                        # Secret / JsReconFinding / Endpoint, values hashed
python3 diff_snapshots.py E0_js.json E1_js.json --updated
python3 validate_js_secrets.py <id> --phase e0             # e0 | p0 | p1 | p2, with --trufflehog on|off
python3 canary_report.py --since <STARTED_AT>              # E3: must report 0
./swap_image.sh slow -- python3 e2e_js_secrets.py --rerun <id> ...   # E7
./swap_image.sh park -- python3 e2e_js_secrets.py --rerun <id> ...   # E8
```

`e2e_js_secrets.py` creates an `internal` IP-mode project over `.10 .11 .12 .14`
(`--with-realkeys` adds `.15` and names it `jslab-validation`) with naabu on 80,
httpx, katana (depth 2, JS crawl) and JS Recon; every AI and Jev hook, Nuclei,
traffic capture, supply chain, OSINT and the dependency check are off. A lab
setting the server does not know is left out by name; a `--set` key is passed
as given, so a setting that is not deployed yet fails loudly. The Priority
Board runs only with `--triage`. The MCP token comes from the repo `.env`
through `../fp_regression_target/mcp_client.py`; `run_partial.py` signs in with
`UI_LOGIN_USERNAME` / `UI_LOGIN_PASSWORD`. Neither prints a credential.

`snapshot.py` and `validate_js_secrets.py` read the graph with `cypher-shell`
inside `redamon-neo4j` (the password stays in the container; muted nodes, which
MCP `query_graph` hides, are included). The validator hashes `matched_text`
inside Neo4j, so no value leaves the database.

`swap_image.sh park|slow` swaps `redamon-trufflehog:latest` only for the
duration of the command after `--`; its trap restores the image on every exit
and keeps the `IMAGE_PARKED` flag of the progress ledger in step. `slow` builds
`slow_trufflehog/` on the parked image: a wrapper that sleeps `SLOW_S` (300)
seconds, then runs the real binary.

### The canary

`.12`'s strings point at the canary's address on `redamon-trufflehog-net`, the
bridge a verifying TruffleHog sidecar uses. `canary_report.py --since <t>`
counts the connections from that bridge's subnet and lists apart those from its
gateway: those come from the host side (a recon container on host networking,
a `curl` from the host), never from a sidecar. A quick self-test:

```bash
t=$(date -u +%FT%TZ); ip=$(docker inspect -f '{{(index .NetworkSettings.Networks "redamon-trufflehog-net").IPAddress}}' jslab-canary)
docker run --rm --network redamon-trufflehog-net alpine sh -c "nc -w1 $ip 5432 </dev/null"
python3 canary_report.py --since "$t"          # 1, on port 5432
```

### Real keys (E3 only)

`python3 -I gen_lab.py --real-keys <api-keys-export>` writes host `.15` into
`_local/internal/temp_fix/js_recon_truffle_e2e/lab_real_keys/` (git-ignored):
each key in its own file next to its provider word (TruffleHog's keyword
prefilter works per file, so a key reaches only its own provider's verifier),
a copy of `.10`, `docker-compose.realkeys.yml` and `expected_real.json`. It runs
TruffleHog offline (`--network none`, no verification) to record which keys it
detects, and prints key names and `sha256[:12]` only. Start `.15` with
`docker compose -f <that file> up -d` just before E3; the E3 cleanup takes it
down and deletes the folder. `./down.sh` also removes a leftover `.15`.

## Files

| File | What |
|---|---|
| `docker-compose.yml` | the four hosts (`python:3.12-slim`, `http.server`, read-only) and the canary |
| `up.sh`, `down.sh` | bring the lab up (network, canary, generation, hosts) and down |
| `gen_lab.py` | the generator; `--emit-expected`, `--check-expected`, `--real-keys` |
| `expected.json` | one row per planted item, by hash |
| `e2e_js_secrets.py`, `run_partial.py` | full recon over MCP; partial recon with an upload over REST |
| `snapshot.py`, `diff_snapshots.py` | graph snapshot (values hashed) and its property-level diff |
| `validate_js_secrets.py` | PASS/FAIL per row and the global checks |
| `canary_report.py` | the canary itself (`--serve`) and its report |
| `swap_image.sh`, `slow_trufflehog/` | the TruffleHog image swap for E7/E8 |

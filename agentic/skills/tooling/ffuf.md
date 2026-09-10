---
name: ffuf playbook
description: ffuf fuzzing reference for path, vhost, parameter, and POST-body discovery with non-interactive defaults and matcher/filter strategy.
---

# ffuf Playbook

Tactical reference for content, vhost, parameter, and POST-body fuzzing with `ffuf`. Pull this in when you need to recall flag interactions, build a noise-tight matcher set, or pick the right wordlist for the surface.

Upstream: https://github.com/ffuf/ffuf

## RedAmon wiring

| Action | Tool | Notes |
|---|---|---|
| Run a fuzz job | `execute_ffuf` | Pass arguments without the leading `ffuf`. Always include `-noninteractive`. |
| Inspect long output files | `kali_shell` | `cat`/`jq` over `/tmp/ffuf_*.json`. |
| Pre-feed wordlists | `kali_shell` | Build target-specific lists with `cewl`, `gau`, or grep over crawl output. |

## Built-in wordlists

```
/usr/share/seclists/Discovery/Web-Content/common.txt              4750 entries (start here)
/usr/share/seclists/Discovery/Web-Content/big.txt                 20481 entries
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt  29999 entries
/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt    37k entries
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

## Canonical shape

```
ffuf -w <wordlist> -u <url_with_FUZZ> [matchers/filters] [transport]
```

The `FUZZ` token must appear at the mutation point. With multiple wordlists use `-w file:KEYWORD` and place `KEYWORD` at the matching slot in URL/header/body.

## Flag reference

| Flag | Purpose |
|---|---|
| `-u <url>` | Target URL containing `FUZZ` |
| `-w <list>` | Wordlist (multiple `-w` allowed when keyworded) |
| `-mc <codes>` | Match status codes (`200,301,302,403`) |
| `-fc <codes>` | Filter status codes |
| `-fs <bytes>` | Filter response size (use against soft-404 baselines) |
| `-fl <lines>` / `-fw <words>` | Filter by line/word count |
| `-ac` | Auto-calibrate against random pseudo-paths (recommended) |
| `-acc <code>` | Calibration string (extra) |
| `-t <n>` | Threads |
| `-rate <n>` | Requests per second (preferred throttle) |
| `-timeout <s>` | Per-request timeout |
| `-recursion` `-recursion-depth <n>` | Recursive directory walking |
| `-H 'Header: val'` | Custom headers |
| `-X <method>` `-d 'body'` | Non-GET fuzzing |
| `-x <proxy>` | HTTP/SOCKS upstream |
| `-ignore-body` | Skip body download (faster on hosts with huge pages) |
| `-noninteractive` | MANDATORY in agent runs |
| `-of json -o <file>` | Structured output for downstream parsing |

## Default safe invocation

```
execute_ffuf args: "-w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://target.tld/FUZZ -mc 200,204,301,302,307,401,403,405 -ac -t 20 -rate 50 -timeout 10 -noninteractive -of json -o /tmp/ffuf_dirs.json"
```

## Recipes

### Path discovery

```
execute_ffuf args: "-w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://target.tld/FUZZ -mc 200,204,301,302,307,401,403 -ac -t 40 -rate 200 -noninteractive -of json -o /tmp/ffuf_paths.json"
```

### Recursive walk on a known root

```
execute_ffuf args: "-w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -u https://target.tld/admin/FUZZ -recursion -recursion-depth 2 -ac -t 30 -noninteractive -of json -o /tmp/ffuf_recursion.json"
```

### Vhost fuzzing (filter the empty-host baseline)

```
execute_ffuf args: "-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u https://target.tld -H 'Host: FUZZ.target.tld' -fs 0 -ac -t 30 -noninteractive -of json -o /tmp/ffuf_vhost.json"
```

### Parameter value fuzzing

```
execute_ffuf args: "-w values.txt -u 'https://target.tld/search?q=FUZZ' -mc all -fs 0 -ac -t 30 -noninteractive -of json -o /tmp/ffuf_param.json"
```

### POST body fuzzing (login form)

```
execute_ffuf args: "-w /usr/share/wordlists/rockyou.txt -u https://target.tld/login -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=admin&password=FUZZ' -fc 401 -t 20 -rate 50 -noninteractive -of json -o /tmp/ffuf_login.json"
```

### Two-keyword sweep (user x pass)

```
execute_ffuf args: "-w users.txt:USER -w /usr/share/wordlists/rockyou.txt:PASS -u https://target.tld/login -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'u=USER&p=PASS' -fc 401 -mode clusterbomb -noninteractive -of json -o /tmp/ffuf_combo.json"
```

### Proxy through the in-sandbox proxy

```
execute_ffuf args: "-w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://target.tld/FUZZ -x http://127.0.0.1:48080 -mc 200,301,302,403 -ac -noninteractive"
```

### Captured traffic (proxy_brain tools)

When HTTP Traffic Capture is enabled, an ffuf run routed through the capture proxy folds every request/response into captured history, queryable afterward via redamon.grep (substring over response bodies) and redamon.query, with no re-run needed. Seed and scope the fuzz to real endpoints with redamon.sitemap (observed paths), redamon.search (matching txns), and redamon.params (params flagged injectable). For single-parameter value fuzzing there is an in-platform analog: redamon.fuzz(id, insertion_point, payloads) replays one captured request across a query param (the Burp-Intruder move, capped at 50, origin host only), and redamon.replay reproduces a single request with mutations.

## Calibration discipline

`-ac` calibrates against a few pseudo-random words to learn the soft-404 fingerprint. If the target returns rotating bodies (timestamps, CSRF tokens) the body size shifts every request and `-ac` becomes useless. Counter measures, in order:

1. Drop `-ignore-body` and add `-fl <lines>` or `-fw <words>` instead of `-fs`.
2. Add `-acc <static-known-bad-string>` to anchor calibration.
3. Filter by regex on response body: `-fr 'not\s+found'`.

## Pitfalls and recovery

- ffuf swallowing follow-up shell input -> always include `-noninteractive`.
- Soft-404 noise -> tighten `-mc/-fc/-fs` before raising load.
- Long runtime -> lower `-rate` and `-t`, narrow scope, switch to `common.txt` first.
- WAF rate-limiting -> drop `-t` to 5-10, `-rate` to 20-30, add `-H 'User-Agent: <real-browser-UA>'`.
- Empty results on host-only input -> the target may require dual-scheme; pre-resolve with `execute_httpx -nf` and feed the live URL list.

## Hand-off

Feed the JSON output into:
- `execute_nuclei -l <urls>` for vuln templates
- `execute_arjun -i <urls> -m GET` for hidden parameter discovery on each new path
- `kali_shell jq -r '.results[].url' /tmp/ffuf_paths.json | sort -u` to flatten to a URL list

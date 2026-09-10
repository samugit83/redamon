---
name: httpx playbook
description: ProjectDiscovery httpx reference covering live-host probing, scheme handling, technology detection, response storage, and JSONL output.
---

# httpx Playbook

Reference for HTTP/S liveness probing, fingerprinting, and stored-response capture. Pull this in when you need to recall flag interactions, reason about dual-scheme probing, or capture raw responses for downstream parsing.

Upstream: https://docs.projectdiscovery.io/opensource/httpx/usage

## RedAmon wiring

| Action | Tool | Notes |
|---|---|---|
| Probe live HTTP/S surface | `execute_httpx` | Pass arguments without the leading `httpx`. |
| Store raw responses for grepping | `execute_httpx -sr -srd <dir>` | Pairs of request/response files written under the directory. |
| Parse JSONL output | `kali_shell` | `jq -c 'select(.tech | index("WordPress"))' /tmp/httpx.jsonl` |

## Canonical shape

```
httpx (-u URL | -l hosts.txt) [probes] [throughput] [output]
```

Hosts can be bare (`target.tld`), CIDR, schemed URLs, or `host:port`. Use `-nf` when input is bare and you want both schemes attempted.

## Flag reference

### Targeting

| Flag | Purpose |
|---|---|
| `-u <target>` | Single host or URL |
| `-l <file>` | Target list (one per line) |
| `-p <ports>` | Custom ports (`80,443,8080,8443`) |
| `-nf` | No-fallback: probe HTTP and HTTPS (do not stop after first hit) |
| `-nfs` | Disable scheme auto-switch |
| `-path <path|file>` | Probe specific path(s) |
| `-vhost` | Vhost detection |

### Probes / response info

| Flag | Purpose |
|---|---|
| `-sc` | Status code |
| `-title` | Page title |
| `-server` | `Server:` header |
| `-td` | Technology detection (Wappalyzer-style) |
| `-cl` | Content length |
| `-ct` | Content type |
| `-location` | `Location:` header |
| `-fr` | Follow redirects |
| `-mc <codes>` | Match status codes |
| `-fc <codes>` | Filter status codes |
| `-fd` | Filter duplicate responses (page hashing) |
| `-method <verb>` | HTTP method |
| `-probe` | Print only `live`/`dead` decision |

### Response storage

| Flag | Purpose |
|---|---|
| `-sr` | Store full request/response pairs |
| `-srd <dir>` | Output directory for stored pairs |

### Throughput

| Flag | Purpose |
|---|---|
| `-rl <n>` | Requests per second |
| `-t <n>` | Threads |
| `-timeout <s>` | Per-request timeout |
| `-retries <n>` | Retries |
| `-proxy <url>` | Upstream proxy |

### Output

| Flag | Purpose |
|---|---|
| `-silent` | Pipeline-friendly output |
| `-j` `-json` | JSONL output |
| `-o <file>` | Output file |
| `-stats` | Periodic progress |
| `-tlsi` | Experimental TLS impersonation |

## Default safe invocation

```
execute_httpx args: "-l /tmp/hosts.txt -sc -title -server -td -fr -timeout 10 -retries 1 -rl 50 -t 25 -silent -j -o /tmp/httpx.jsonl"
```

## Recipes

### Quick liveness + fingerprint

```
execute_httpx args: "-l /tmp/hosts.txt -sc -title -server -td -silent -o /tmp/httpx.txt"
```

### Probe both schemes from bare hosts

```
execute_httpx args: "-l /tmp/hosts.txt -nf -sc -title -td -silent -j -o /tmp/httpx_dual.jsonl"
```

### Probe known admin paths

```
execute_httpx args: "-l /tmp/hosts.txt -path /,/login,/admin,/dashboard,/api,/api/docs,/.git/config,/.env -sc -title -silent -j -o /tmp/httpx_paths.jsonl"
```

### Vhost discovery sweep

```
execute_httpx args: "-l /tmp/hosts.txt -vhost -sc -title -silent -j -o /tmp/httpx_vhost.jsonl"
```

### Custom ports

```
execute_httpx args: "-l /tmp/hosts.txt -p 80,443,8000,8080,8443,9000,9090 -sc -title -td -silent -j -o /tmp/httpx_ports.jsonl"
```

### Store raw responses for grep / JS extraction

```
execute_httpx args: "-l /tmp/hosts.txt -fr -sr -srd /tmp/httpx_store -sc -title -server -cl -ct -location -probe -silent -j -o /tmp/httpx_full.jsonl"
```

The `httpx_store/` tree holds `<host>/req.txt` and `<host>/resp.txt` pairs. Useful for `grep -RE 'api[_-]?key|secret|token' /tmp/httpx_store`.

### Captured traffic (proxy_brain tools)

When HTTP Traffic Capture is enabled and httpx routes through the capture proxy (via `-proxy`), its probes fold into captured history. The `-sr -srd` plus grep-for-secrets move then has a direct in-platform analog: redamon.grep(pattern) runs the same substring search across captured response bodies, and the URL/status/tech inventory overlaps redamon.search (filter by host, method, statusClass) and redamon.sitemap (distinct observed endpoints). Query captured traffic with proxy_brain instead of re-probing, no re-run needed.

### Authenticated probing

```
execute_httpx args: "-l /tmp/hosts.txt -H 'Authorization: Bearer <token>' -H 'Cookie: session=...' -sc -title -td -silent -j -o /tmp/httpx_auth.jsonl"
```

### Through a proxy (Burp / mitmproxy in sandbox)

```
execute_httpx args: "-l /tmp/hosts.txt -proxy http://127.0.0.1:48080 -sc -title -silent -j -o /tmp/httpx_proxy.jsonl"
```

## Output fields worth filtering on

A typical JSONL line looks like:

```
{"timestamp":"...", "url":"https://target.tld", "input":"target.tld", "scheme":"https",
 "status_code":200, "title":"Acme", "tech":["nginx","React"], "webserver":"nginx",
 "content_length":1234, "content_type":"text/html", ... }
```

Common downstream extractions:

```
kali_shell: jq -r 'select(.status_code==200) | .url' /tmp/httpx.jsonl > /tmp/live.txt
kali_shell: jq -r 'select(.tech | index("WordPress")) | .url' /tmp/httpx.jsonl > /tmp/wordpress.txt
kali_shell: jq -r 'select(.status_code>=400 and .status_code<500) | "\(.status_code)\t\(.url)"' /tmp/httpx.jsonl
```

## Pitfalls and recovery

- Empty output on bare hostnames -> add `-nf` so both `http://` and `https://` are tried.
- Many timeouts -> raise `-timeout` (try 20s) and lower `-t/-rl`.
- Output noisy with redirect-only entries -> add `-fr` so probes settle on the final URL, then `-fd` to drop duplicates.
- Tech detection misses obvious stack -> add `-td` and rerun; without that flag, no detection runs.
- Cannot probe a custom non-default port -> add it via `-p`; httpx will not infer non-standard ports.

## Hand-off

```
execute_httpx -l hosts.txt -sc -title -td -silent -j -o /tmp/httpx.jsonl
   -> jq -r .url /tmp/httpx.jsonl | sort -u > /tmp/live.txt
   -> execute_katana -list /tmp/live.txt -d 3 -jc -j -o /tmp/katana.jsonl
   -> execute_nuclei -l /tmp/live.txt -as -j -o /tmp/nuclei.jsonl
```

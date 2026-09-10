---
name: katana playbook
description: Katana crawler reference covering depth/JS-aware crawling, headless mode, known-files mode, and proxy-instrumented runs.
---

# Katana Playbook

Reference for endpoint discovery via the Katana crawler: depth tuning, JS-discovered endpoints, headless rendering, known-file modes, and structured JSONL output. Pull this in when you need to recall flag interactions, reason about the cost of `-jsl`, or pipe crawl output into ffuf/nuclei/jsluice.

Upstream: https://docs.projectdiscovery.io/opensource/katana/usage

## RedAmon wiring

| Action | Tool | Notes |
|---|---|---|
| Run a crawl | `execute_katana` | Pass arguments without the leading `katana`. |
| JS-aware extraction on captured files | `kali_shell jsluice` | After `execute_curl -s -o /tmp/app.js URL`, run `jsluice urls /tmp/app.js`. |
| Pipe URL list into the next step | `kali_shell` | `jq -r '.endpoint' /tmp/katana.jsonl | sort -u > /tmp/urls.txt` |

## Canonical shape

```
katana (-u URL | -list file) [depth/js] [throughput] [output]
```

Always create the output directory before passing `-o /tmp/dir/file.jsonl`; Katana errors out instead of creating it.

## Flag reference

### Targeting and depth

| Flag | Purpose |
|---|---|
| `-u <url>` `-list <file>` | Single or list of root URLs |
| `-d <n>` | Crawl depth (default 3 is a good baseline) |
| `-jc` | Parse JavaScript-discovered endpoints |
| `-jsl` | Deeper JS parsing via jsluice (memory intensive; use only when needed) |
| `-kf <mode>` | Known-files mode: `all`, `robotstxt`, or `sitemapxml` |
| `-xhr` | Extract XHR endpoints into JSONL |
| `-ef <list>` | Extension filter (skip static files) |
| `-fs <list>` | Field scope (`rdn` root domain, `dn` domain, `fqdn`) |
| `-cs <regex>` | Custom in-scope regex |
| `-ns` | No scope (follow off-host; rarely useful) |

### Headless / browser

| Flag | Purpose |
|---|---|
| `-hl` | Hybrid headless crawling (uses bundled Chromium) |
| `-sc` | Use system Chrome instead of bundled |
| `-nos` | `--no-sandbox` (required in container) |
| `-noi` | Disable incognito (persists session) |
| `-cdd <dir>` | Persistent Chrome data dir (auth state) |
| `-ho 'k=v,...'` | Comma-separated Chrome options (e.g. `proxy-server=http://...`) |

### Throughput

| Flag | Purpose |
|---|---|
| `-c <n>` | Concurrent fetchers per target |
| `-p <n>` | Parallelism across input targets |
| `-rl <n>` | Rate limit (req/s) |
| `-timeout <s>` | Per-request timeout |
| `-retry <n>` | Retry count |

### Output

| Flag | Purpose |
|---|---|
| `-silent` | Suppress banner and progress |
| `-j` `-jsonl` | JSONL output (preferred for downstream) |
| `-o <file>` | Output path |
| `-tlsi` | Experimental TLS impersonation (JA3 reshape) |

## Default safe invocation

```
kali_shell: mkdir -p /tmp/katana
execute_katana args: "-u https://target.tld -d 3 -jc -kf robotstxt -c 10 -p 10 -rl 50 -timeout 10 -retry 1 -ef png,jpg,jpeg,gif,svg,css,woff,woff2,ttf,eot,map -silent -j -o /tmp/katana/run.jsonl"
```

## Recipes

### Fast crawl baseline

```
execute_katana args: "-u https://target.tld -d 3 -jc -silent -o /tmp/katana_urls.txt"
```

### Deeper JS-aware crawl

```
execute_katana args: "-u https://target.tld -d 5 -jc -jsl -kf all -c 10 -p 10 -rl 50 -j -o /tmp/katana_deep.jsonl"
```

### Multi-target crawl

```
execute_katana args: "-list /tmp/roots.txt -d 3 -jc -silent -j -o /tmp/katana_multi.jsonl"
```

### Headless crawl in the sandbox

```
execute_katana args: "-u https://target.tld -hl -nos -xhr -j -o /tmp/katana_headless.jsonl"
```

`-nos` is mandatory in container runs. Drop `-sc` unless system Chrome is installed; the bundled Chromium is the default path.

### Headless via in-sandbox proxy (Burp-style instrumentation)

```
execute_katana args: "-u https://target.tld -hl -nos -ho proxy-server=http://127.0.0.1:48080 -j -o /tmp/katana_proxy.jsonl"
```

### Authenticated crawl with persistent profile

```
execute_katana args: "-u https://target.tld -hl -nos -noi -cdd /tmp/katana_profile -j -o /tmp/katana_auth.jsonl"
```

Bootstrap the profile once via `execute_playwright` (login flow), then point Katana at the same data dir.

### Captured traffic (proxy_brain tools)

When HTTP Traffic Capture is enabled and Katana crawls through the capture proxy, the crawl folds into captured history and becomes queryable via redamon.search (host/method/status filters) and redamon.grep (substring over response bodies). The crawl output overlaps redamon.sitemap (distinct observed endpoints) and redamon.params (distinct params, POST bodies included), so redamon.sitemap can dedupe what is already seen and seed only the paths Katana still needs to reach, no re-crawl needed to inspect what was captured.

## Known-files mode (`-kf`)

`-kf` controls which "well-known" sources Katana consults to seed the crawl. Combine with sufficient `-d`:

| Value | Includes |
|---|---|
| `robotstxt` | `/robots.txt` allow/disallow paths |
| `sitemapxml` | `/sitemap.xml`, `sitemap_index.xml`, nested sitemaps |
| `all` | Both |

Lower `-d` swallows known-file paths beyond the immediate root; keep `-d >= 3` when using `-kf`.

## Throughput tuning

- Memory spikes -> drop `-jsl`, lower `-c` and `-p`.
- Crawl never ends -> tighten `-d`, add `-ct <max-time>` (built-in crawl timeout in seconds).
- Hammering a fragile target -> `-rl 10 -c 3 -p 3` is a safe floor.
- Static-file noise drowns endpoints -> add `-ef png,jpg,jpeg,gif,svg,css,woff,woff2,ttf,eot,map,ico,pdf`.
- Need only HTML routes (no JS) -> drop `-jc -jsl`.

## Common pitfalls

- Katana exits early with "no scope" -> set `-fs rdn` (root-domain match) explicitly.
- `-o` errors with `no such file or directory` -> parent must exist (`mkdir -p` first).
- `-proxy` and `-ho proxy-server=...` collide in headless mode -> use `-ho` for headless, `-proxy` for HTTP-only crawls.
- JSONL has duplicate URLs -> Katana emits one record per request method/source; deduplicate downstream with `jq -r '.endpoint' | sort -u`.
- Headless run hangs after a few minutes -> Chromium child died (memory). Lower `-c` to 3-5, drop `-jsl`.

## Hand-off

```
kali_shell: jq -r '.endpoint' /tmp/katana/run.jsonl | sort -u > /tmp/katana_urls.txt
kali_shell: jq -r 'select(.method=="POST") | .endpoint' /tmp/katana/run.jsonl > /tmp/katana_post_endpoints.txt
```

Feed `katana_urls.txt` into:
- `execute_httpx -l /tmp/katana_urls.txt -td -sc -title -j -o /tmp/httpx_after_katana.jsonl`
- `execute_nuclei -l /tmp/katana_urls.txt -as -j -o /tmp/nuclei_after_katana.jsonl`
- `execute_arjun -i /tmp/katana_urls.txt -m GET -oJ /tmp/arjun.json` for hidden-parameter discovery.

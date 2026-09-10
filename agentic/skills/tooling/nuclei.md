---
name: nuclei playbook
description: Nuclei command-line reference for bounded template-driven scanning, severity filtering, OAST controls, and JSONL output for downstream parsing.
---

# Nuclei Playbook

Reference for template selection, throughput limits, OAST handling, and structured output when driving Nuclei. Pull this in when you need to recall flag interactions, decide between `-as` and explicit `-t/-tags`, or tune for a noisy/locked-down target.

Upstream: https://docs.projectdiscovery.io/opensource/nuclei/running

## RedAmon wiring

| Action | Tool | Notes |
|---|---|---|
| Run scans | `execute_nuclei` | Pass arguments without the leading `nuclei`. |
| Update template store | `kali_shell` | `nuclei -update-templates` (run sparingly; templates are baked at image build). |
| Parse JSONL findings | `kali_shell` | `jq -c 'select(.info.severity=="high")' /tmp/nuclei.jsonl`. |

## Canonical shape

```
nuclei (-u URL | -l targets.txt) (template selection) (throughput) (output)
```

A template selection method is required. Pick exactly one of:
- `-as` automatic scan (Nuclei maps detected stack to relevant templates)
- `-t <path|tag>` explicit template path or directory
- `-tags <tag1,tag2>` template-tag filter

## Flag reference

| Flag | Purpose |
|---|---|
| `-u <url>` | Single target |
| `-l <file>` | Target list (one host or URL per line) |
| `-im <mode>` | Input format: `list`, `burp`, `jsonl`, `yaml`, `openapi`, `swagger` |
| `-t <path>` | Template path or directory |
| `-tags <list>` | Template tags (`cve,misconfig,exposure`) |
| `-s <severity>` | Severity filter (`critical,high,medium,low,info,unknown`) |
| `-as` | Tech-aware automatic scan |
| `-ni` | Disable interactsh / OAST |
| `-iserver <url>` | Custom OAST server |
| `-rl <n>` | Global request rate cap |
| `-c <n>` | Template concurrency |
| `-bs <n>` | Bulk size: hosts in parallel per template |
| `-timeout <s>` | Per-request timeout |
| `-retries <n>` | Retries (keep at 1 for predictable runtime) |
| `-stats` | Periodic stats line |
| `-silent` | Findings-only output |
| `-j` | JSONL output |
| `-o <file>` | Output file |
| `-H 'k: v'` | Add headers (auth) |
| `-V 'k=v'` | Set DSL variable |

## Default safe invocation

```
execute_nuclei args: "-l /tmp/targets.txt -as -s critical,high -rl 50 -c 20 -bs 20 -timeout 10 -retries 1 -silent -j -o /tmp/nuclei.jsonl"
```

## Recipes

### Targeted CVE sweep on a single host

```
execute_nuclei args: "-u https://target.tld -tags cve -s critical,high -silent -j -o /tmp/nuclei_cve.jsonl"
```

### Tag-driven misconfig + exposure pass

```
execute_nuclei args: "-l /tmp/targets.txt -tags misconfig,exposure -s high,medium -rl 30 -c 10 -bs 10 -silent -j -o /tmp/nuclei_misconfig.jsonl"
```

### Explicit template directory

```
execute_nuclei args: "-l /tmp/targets.txt -t http/cves/2024/ -t http/cves/2025/ -t dns/ -rl 30 -c 10 -bs 10 -j -o /tmp/nuclei_explicit.jsonl"
```

### OAST-disabled run (no outbound callbacks)

```
execute_nuclei args: "-l /tmp/targets.txt -as -s critical,high -ni -stats -rl 30 -c 10 -bs 10 -timeout 10 -retries 1 -j -o /tmp/nuclei_no_oast.jsonl"
```

Use `-ni` whenever the target cannot reach the public internet, when interactsh would generate compliance noise, or when you are scanning an isolated lab. Without `-ni`, time-based and OOB-confirmed templates fire callbacks against `oast.fun`.

### Custom OAST server

```
execute_nuclei args: "-l /tmp/targets.txt -as -iserver oast.attacker-controlled.tld -j -o /tmp/nuclei_custom_oast.jsonl"
```

### Authenticated scan

```
execute_nuclei args: "-l /tmp/targets.txt -as -s critical,high -H 'Authorization: Bearer <token>' -H 'Cookie: session=...' -silent -j -o /tmp/nuclei_auth.jsonl"
```

### OpenAPI / Swagger spec input

```
execute_nuclei args: "-l /tmp/openapi.yaml -im openapi -as -j -o /tmp/nuclei_api.jsonl"
```

### Captured traffic (proxy_brain tools)

When HTTP Traffic Capture is enabled, `-im burp` (alongside `-im openapi/swagger`) lets Nuclei consume captured traffic as input: build the target/URL list from redamon.sitemap (distinct observed endpoints) and redamon.search (filtered txns) rather than re-crawling. After a run, cross-check each finding's matched-at URL against what was actually captured with redamon.grep (substring over response bodies) and redamon.query, confirming the hit without re-running the tool.

## Throughput tuning ladder

Tune in this order when the run is too aggressive or too slow:

1. Lower `-c` (template concurrency) before lowering `-rl`. Concurrency buys parallelism per template; rate caps total RPS.
2. Lower `-bs` (hosts in parallel per template) when the target list is large but per-host fragility is the bottleneck.
3. Cap retries (`-retries 1`) by default; raise only when transient errors are proven (timeout != fragility).
4. Increase `-timeout` when responses are slow but stable. Default 10s is good for most surfaces.

## Common pitfalls

- Empty findings -> verify the template path exists, run `-stats` to see how many requests fired, and confirm `-as` mapped at least one tech.
- OAST stuck on "wait for callback" -> add `-ni` if the egress is blocked.
- Duplicate alerts across runs -> add `-deduplicate` (built-in; on by default in newer versions).
- Long runtime on `cve.*` tags -> bound severity (`-s critical,high`) and prefer per-year `-t http/cves/2024/`.
- Templates not finding obvious tech -> rerun with `-debug` once on a small list, then revert.

## Hand-off

```
kali_shell: jq -c 'select(.info.severity=="critical" or .info.severity=="high")' /tmp/nuclei.jsonl > /tmp/nuclei_top.jsonl
kali_shell: jq -r '.matched-at' /tmp/nuclei.jsonl | sort -u > /tmp/nuclei_urls.txt
```

Push high-confidence hits into the graph via `query_graph` follow-up, or feed URLs into `execute_curl` / `metasploit_console` for confirmation.

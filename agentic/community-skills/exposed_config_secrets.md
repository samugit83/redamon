# Exposed Config and Secret Files Attack Skill

Discovery and triage of configuration, version-control, and backup artifacts left reachable on an external web surface (e.g. `.git/`, `.env`, `.svn/`, `appsettings.json`, `wp-config.php.bak`, `docker-compose.yml`, `.DS_Store`, cloud credential files, editor swap files). Drives an enumerate -> probe -> fingerprint -> confirm pipeline across a host or domain, grades each hit by whether it leaks live secrets, and stops at the minimum proof needed to show real exposure.

## When to Classify Here

Use this skill when the operator wants to find sensitive files that a web server is serving by accident, including:

- "Check for an exposed `.git` directory on `target.tld`"
- "Look for `.env` / config files leaking on the external surface"
- "Find backup and swap files (`.bak`, `.old`, `~`, `.swp`) next to the app"
- "Scan for exposed `.svn`, `.hg`, `.DS_Store`, or `WEB-INF` listings"
- "Is the deploy leaking `docker-compose.yml`, `appsettings.json`, or `settings.py`?"
- "Hunt for cloud credential files (`.aws/credentials`, `gcloud` keys) on the host"
- "Triage whether an exposed config file actually contains live secrets"

Keywords (kept disjoint from neighboring skills): exposed config, exposed secret, dotenv leak, env file exposure, git directory exposure, dot git exposed, source code leak, backup file exposure, bak file, swap file leak, svn exposure, ds_store, web-inf exposure, appsettings leak, wp-config backup, credential file exposure, config disclosure, sensitive file exposure.

### Boundary against neighboring skills

- Not community `path_traversal`: that skill abuses `../` sequences and LFI sinks to escape an intended directory. This skill requests files the server already publishes at their normal path; no traversal payload is involved. Pivot to `path_traversal` only if reaching the file needs a traversal primitive.
- Not built-in `cve_exploit`: an exposed file is a misconfiguration, not a software CVE. Stay here whenever the entry point is a reachable config, source, or backup artifact. Pivot to `cve_exploit` only if a secret recovered here unlocks a separate, CVE-bearing service.
- Not community `ssrf_exploitation`: SSRF abuses a server-side fetcher. This skill fetches files directly as the client.
- Not community `subdomain_takeover`: that skill claims dangling hostnames on the DNS / provider plane. This skill operates on the HTTP layer of a host the org already controls.
- Not built-in `access_control` / community `broken_access_control`: those probe authorization boundaries on live endpoints. An exposed file needs no auth to read; it is served openly.

## Tools

- `execute_httpx`: probe candidate paths at scale, capture status, length, and content type.
- `execute_ffuf`: fuzz a path list against the host to enumerate reachable artifacts.
- `execute_nuclei`: run the exposure and misconfiguration template families for a first pass.
- `execute_katana` and `execute_gau`: harvest known paths and historical URLs that hint at config or backup naming.
- `execute_curl`: fetch a single confirmed artifact and inspect bytes during triage.
- `kali_shell`: reconstruct or parse a recovered artifact (e.g. read a `.git/config`, diff a `.bak`) in the sandbox.
- `query_graph`: pull the existing host, port, and technology inventory so probing targets only live surfaces.
- `google_dork`: surface indexed config or backup files without touching the target.

## Workflow

### Phase 1: Discovery (Informational)

Goal: list every reachable config, source-control, or backup artifact, with no attempt yet to read secret values.

1. Pull the known surface from the recon graph so you probe live hosts and ports only:

```
query_graph: return the hosts, open HTTP/HTTPS ports, and detected technologies for the current target scope
```

2. Seed candidate paths from history and crawl before brute force (quieter, and it reveals real naming conventions):

```
execute_gau: collect historical URLs for the target domain
execute_katana: crawl each live host for linked paths and reference leaks
```

3. Probe the high-signal, low-noise paths first with httpx. Grade on status plus content type, not status alone (a 200 serving the app's HTML is a soft 404):

```
execute_httpx: probe these paths on each live host and report status, content-length, content-type, and title
  /.git/HEAD
  /.git/config
  /.env
  /.svn/entries
  /.hg/requires
  /.DS_Store
  /WEB-INF/web.xml
  /docker-compose.yml
  /appsettings.json
  /config.php.bak
  /wp-config.php.bak
  /settings.py
  /.aws/credentials
```

4. Broaden with a focused fuzz over a backup and config wordlist, then with the exposure template family:

```
execute_ffuf: fuzz a config/backup path list against each live host, filter out the soft-404 length
execute_nuclei: run the exposures and misconfiguration template tags against the live hosts
```

5. Record each hit as a candidate with its evidence (path, status, content type, size). A directory index, a raw `.git/HEAD` reading `ref: refs/heads/...`, or a `.env` served as `text/plain` are strong candidates; an HTML page is almost always a false positive.

When discovery is complete and at least one candidate shows a strong signal, request transition to exploitation phase.

### Phase 2: Confirmation (Authorized-Only)

Goal: prove a candidate is a real exposure by retrieving the minimum evidence, then stop. Do not bulk-download repositories or exfiltrate secret stores.

1. For an exposed `.git` directory, confirm it is a readable repository rather than an empty folder:

```
execute_curl: fetch /.git/config and /.git/HEAD and show the bytes
```

A valid `[core]` block in `config` and a `ref:` line in `HEAD` confirm the exposure. Note in the report that full source history is recoverable; reconstruct at most a file listing in the sandbox as proof, not the whole tree:

```
kali_shell: parse the fetched .git/config and HEAD to record repo layout (no mass clone)
```

2. For a `.env` or other config artifact, fetch it once and confirm it carries live-looking secrets (populated keys, not placeholders):

```
execute_curl: fetch the candidate file once and display it
```

Redact the secret values in your notes. Recording the key names and the fact that values are populated is sufficient proof; never paste full credential values into the report.

3. Stop at confirmation. Do not use any recovered secret to authenticate to another service in this skill; that is a separate, separately-authorized action.

### Phase 3: Triage and Severity

Grade each confirmed exposure so the report leads with real risk:

- Critical: live cloud credentials, database passwords, signing keys, or a complete `.git` enabling full source recovery.
- High: application secrets or API tokens that are populated and current.
- Medium: source or config disclosure with no live secret (structure and logic leak only).
- Informational: a candidate that turned out to be a false positive or an empty artifact.

## Reporting Guidelines

- One finding per distinct exposed artifact, with the exact URL, HTTP status, content type, and size.
- State the proof you retrieved and keep it minimal: key names with redacted values, or a repo layout, never full secret values or a cloned tree.
- Give severity from the triage grade above, and name the concrete impact (e.g. "AWS key present and populated", "full source recoverable via exposed .git").
- Recommend the fix: remove the artifact from the web root, block the path family at the server or CDN, rotate any exposed secret, and add a deploy check.
- List what was not done (no secret reuse, no bulk download) so the boundary of the test is clear.

## Important Notes

- Prefer crawl and history over brute force first; it is quieter and reveals real naming conventions.
- Treat a 200 that returns the app's HTML as a false positive. Confirm on content type and body shape, not status code alone.
- Retrieve the minimum needed to prove exposure. Do not clone whole repositories or download entire secret stores.
- Never paste full credential values into logs or the report; record key names with values redacted.
- Rate limit the probing against production surfaces; a config/backup wordlist can be large.
- Any reuse of a recovered secret against another service is out of scope here and needs its own authorization.

## vs. path_traversal (community)

If reaching the file requires a `../` traversal or an LFI sink rather than a direct published path, disable or skip this skill and use `path_traversal` instead.

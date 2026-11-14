# Exposed File Discovery Attack Skill

Active, self-contained discovery of exposed configuration, version-control, and backup artifacts (`.git/`, `.env`, `.svn/`, `.hg/`, `appsettings.json`, `wp-config.php.bak`, `.DS_Store`, `WEB-INF/`) on an external host when the recon route-exposure scan has not already found them. Enumerates candidates by probing the live surface, classifies each by kind without reading its contents, then hands proof and secret validation to the built-in `path_traversal` skill. This is the discovery half of the exposed-files pipeline; `path_traversal` is the proof half.

## When to Classify Here

Use this skill when the operator wants to actively find exposed files on a host and the passive route-exposure scan is off (the default) or has not run, including:

- "Check this host for an exposed `.git` or `.env` even though the exposure scan is off"
- "Actively enumerate config, source-control, and backup files on `target.tld`"
- "Nothing is in the graph yet; probe the web root for `.bak`, `.old`, `.swp`, `.DS_Store`"
- "Discover `.svn`/`.hg`, `WEB-INF`, `appsettings.json`, `settings.py` candidates to feed path_traversal"
- "Find exposed-file candidates first, then prove them"

Keywords (kept disjoint from neighbouring skills): exposed file discovery, enumerate exposed files, find exposed config, discover dotenv, probe for git directory, config file enumeration, backup file enumeration, exposure scan off, route exposure disabled, candidate exposed files, exposed file recon.

### Disjoint from neighbouring skills

- vs. `path_traversal` (built-in): the built-in owns the proof half. It consumes exposed-file candidates already in the recon graph (`vcs_exposure`, `env_file`, `config_file`, `backup_file`, `secret_in_response`) and proves them (inflates a loose `.git` object, counts `.env` keys in the sandbox, validates a recovered secret). It does not actively discover those candidates when the route-exposure scan is off. This skill does only that discovery, then defers. Because both compete in the Intent Router, disable the built-in `path_traversal` on import if you want discovery routed here predictably, and re-enable it for the proof follow-up.
- Not community `path_traversal`: that skill abuses `../` sequences, LFI/RFI sinks, and PHP wrappers to escape an intended directory. This skill requests files the server already publishes at their normal path; no traversal primitive is involved.
- Not community `subdomain_takeover`: that operates on the DNS / provider plane. This skill works on the HTTP layer of a host the org already controls.
- Not built-in `access_control`: an exposed file needs no auth to read; this skill never probes an authorization boundary.

## Tools

- `query_graph`: check whether recon already recorded exposed-file candidates before probing anything.
- `execute_gau` and `execute_katana`: seed candidate paths from historical URLs and a crawl, so probing follows real naming conventions before brute force.
- `execute_httpx`: probe candidate paths at scale and capture status, content-length, content-type, and title.
- `execute_ffuf`: fuzz a config/backup path list against the host, filtering the soft-404 length.
- `execute_nuclei`: run the exposure and misconfiguration template families for a first pass.
- `execute_curl`: issue a HEAD or a tiny `Range` request to read only an artifact's magic bytes during classification (never its full body).
- `execute_code`: classify a probe response by status, content-type, size, and magic bytes in the sandbox, with no secret value entering the model context.

## Workflow

### Phase 1: Check what recon already has

Goal: do not re-discover what the route-exposure scan already found. If candidates exist, this is the built-in `path_traversal`'s job, not this skill's.

```
query_graph: return any nodes of kind vcs_exposure, env_file, config_file, backup_file, or secret_in_response for the current target scope, with their URLs and status
```

If that returns candidates, stop here and defer to `path_traversal` to prove them. Only continue to Phase 2 when the graph has none (the route-exposure scan is off or has not run).

When the graph has no candidates, request transition to exploitation phase.

### Phase 2: Active discovery (route-exposure scan off)

Goal: enumerate reachable config, source-control, and backup artifacts, classifying each by kind on existence and shape alone. Never read a file's contents here.

1. Seed from history and a crawl first (quieter, and it reveals real naming):

```
execute_gau: collect historical URLs for the target domain
execute_katana: crawl each live host for linked paths and reference leaks
```

2. Probe the high-signal paths and grade on status plus content type, since a 200 serving the app's HTML is a soft 404:

```
execute_httpx: probe these paths on each live host, report status, content-length, content-type, title
  /.git/HEAD
  /.git/config
  /.env
  /.svn/wc.db
  /.hg/requires
  /.DS_Store
  /WEB-INF/web.xml
  /appsettings.json
  /config.php.bak
  /wp-config.php.bak
  /settings.py
```

3. Broaden with a focused fuzz and the exposure template family:

```
execute_ffuf: fuzz a config/backup path list against each live host, filter out the soft-404 content-length
execute_nuclei: run the exposures and misconfiguration template tags against the live hosts
```

4. Classify each hit by kind using only existence and shape, not the body. Read at most the first bytes with a bounded `Range`:

```
execute_curl: HEAD each candidate, then GET with header "Range: bytes=0-15" to capture magic bytes only
execute_code: from status, content-type, size, and those magic bytes, label each candidate vcs_exposure | env_file | config_file | backup_file, and drop soft-404s
```

A raw `/.git/HEAD` that reads `ref: refs/heads/...`, a `.svn/wc.db` with the SQLite magic, or a `.env` served as `text/plain` are strong candidates. An HTML page is almost always a false positive.

### Phase 3: Hand off to path_traversal for proof

Goal: record the candidate list and let the built-in do what it does well. Do not prove, read, or validate here.

- Record each labelled candidate (URL, status, content-type, size, kind) so it is available as an exposed-file candidate for proof.
- For a `.git` candidate, do not try to prove it here: a `ref:` line or a `[core]` block does not prove a live repository, and the built-in proves it correctly by inflating one loose object. Flag it as `vcs_exposure` and stop.
- Re-enable the built-in `path_traversal` (or run the "prove the exposed files" follow-up) to inflate the `.git` object, count `.env` keys in the sandbox, and validate any secret. Those steps keep values out of the model context, which is why this skill leaves them to the built-in.

## Reporting Guidelines

- One finding per distinct candidate, with the exact URL, HTTP status, content type, size, and the kind label.
- Report discovery results only: that an artifact exists and what kind it is. Do not include file contents or secret values; proof and any redacted key names come from the `path_traversal` follow-up.
- Give each candidate a provisional severity by kind (vcs_exposure / env_file high, config_file / backup_file medium) and mark it "pending proof".
- Recommend the fix: remove the artifact from the web root, block the path family at the server or CDN, and enable the route-exposure scan so this is caught automatically.
- List what was not done (no file bodies read, no secret validated, no `.git` mirrored) so the boundary is clear.

## Important Notes

- Phase 1 is mandatory: if recon already has candidates, this skill defers to `path_traversal` and does nothing.
- Discovery is existence and shape only. Never fetch a full file body or display a `.env`; use HEAD and a bounded `Range` for magic bytes.
- Treat a 200 that returns the app's HTML as a false positive. Confirm on content type and body shape, not status alone.
- Never `git clone`, `wget -r`, or otherwise mirror an exposed `.git`. Flag it and hand proof to the built-in.
- Rate limit the probing against production surfaces; a config/backup wordlist can be large.
- Black-box only: assume no knowledge of the target's internal paths beyond what probing and the graph reveal.

